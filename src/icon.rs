//! Tray icons, drawn in code rather than looked up in the icon theme.
//!
//! A themed icon name is only as good as the theme the user happens to have;
//! a missing name means a missing tray icon, which for this application would
//! mean no visible indication that the screen is being shared. Drawing the
//! glyph ourselves makes the indicator unconditional, and lets the colour
//! carry the state.

use crate::ipc::State;

/// Tray icons are requested at 22px by most hosts; 24 divides more cleanly.
const SIZE: i32 = 24;

/// Colour per state, as 0xRRGGBB.
///
/// Deliberately distinguishable by brightness as well as hue, so the state is
/// still readable for a user who cannot separate amber from red.
const OFF: u32 = 0x9a_a0_a6; // grey: nothing is shared
const LISTENING: u32 = 0xf5_a6_23; // amber: armed, waiting
const CONNECTED: u32 = 0xe5_39_35; // red: someone is watching

pub fn colour_for(state: State) -> u32 {
    match state {
        State::Off => OFF,
        State::Listening => LISTENING,
        State::Connected => CONNECTED,
    }
}

/// Render the tray glyph for `state`.
///
/// The glyph is a monitor outline; when someone is connected it is filled, so
/// the "being watched" state reads differently in shape as well as colour.
pub fn render(state: State) -> ksni::Icon {
    let colour = colour_for(state);
    let filled = matches!(state, State::Connected);
    ksni::Icon {
        width: SIZE,
        height: SIZE,
        data: draw(SIZE, colour, filled),
    }
}

/// Produce ARGB32 pixels in network byte order, i.e. `[A, R, G, B]`.
fn draw(size: i32, colour: u32, filled: bool) -> Vec<u8> {
    let mut data = vec![0u8; (size * size * 4) as usize];

    // Screen body, inset to leave room for the stand below it.
    let left = 2;
    let right = size - 3;
    let top = 3;
    let bottom = size - 8;
    let border = 2;

    // Stand: a short neck plus a wider foot.
    let neck_left = size / 2 - 2;
    let neck_right = size / 2 + 1;
    let foot_left = left + 3;
    let foot_right = right - 3;
    let foot_top = size - 4;

    for y in 0..size {
        for x in 0..size {
            let in_screen = x >= left && x <= right && y >= top && y <= bottom;
            let in_screen_border = in_screen
                && (x < left + border
                    || x > right - border
                    || y < top + border
                    || y > bottom - border);
            let in_neck = x >= neck_left && x <= neck_right && y > bottom && y < foot_top;
            let in_foot = x >= foot_left && x <= foot_right && y >= foot_top && y < size - 1;

            let alpha: u8 = if in_screen_border || in_neck || in_foot {
                0xff
            } else if in_screen {
                // The interior is a wash when idle and solid when connected.
                if filled { 0xff } else { 0x3a }
            } else {
                0x00
            };

            if alpha == 0 {
                continue;
            }
            let i = ((y * size + x) * 4) as usize;
            data[i] = alpha;
            data[i + 1] = ((colour >> 16) & 0xff) as u8;
            data[i + 2] = ((colour >> 8) & 0xff) as u8;
            data[i + 3] = (colour & 0xff) as u8;
        }
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(icon: &ksni::Icon, x: i32, y: i32) -> (u8, u8, u8, u8) {
        let i = ((y * icon.width + x) * 4) as usize;
        (
            icon.data[i],
            icon.data[i + 1],
            icon.data[i + 2],
            icon.data[i + 3],
        )
    }

    #[test]
    fn icons_are_well_formed_argb32() {
        for state in [State::Off, State::Listening, State::Connected] {
            let icon = render(state);
            assert_eq!(icon.width, SIZE);
            assert_eq!(icon.height, SIZE);
            assert_eq!(
                icon.data.len(),
                (SIZE * SIZE * 4) as usize,
                "ARGB32 needs exactly four bytes per pixel"
            );
        }
    }

    #[test]
    fn every_state_is_a_different_colour() {
        let colours: std::collections::HashSet<u32> =
            [State::Off, State::Listening, State::Connected]
                .into_iter()
                .map(colour_for)
                .collect();
        assert_eq!(colours.len(), 3, "states must be visually distinguishable");
    }

    #[test]
    fn state_colour_reaches_the_pixels() {
        let icon = render(State::Connected);
        // A point on the top border of the screen outline.
        let (a, r, g, b) = pixel(&icon, SIZE / 2, 4);
        assert_eq!(a, 0xff, "the outline must be fully opaque");
        assert_eq!((r, g, b), (0xe5, 0x39, 0x35));
    }

    #[test]
    fn connected_is_filled_and_listening_is_not() {
        let centre = (SIZE / 2, 8);
        let listening = pixel(&render(State::Listening), centre.0, centre.1);
        let connected = pixel(&render(State::Connected), centre.0, centre.1);
        assert_eq!(connected.0, 0xff, "connected should be solid");
        assert!(
            listening.0 > 0 && listening.0 < 0xff,
            "listening should be a wash, got alpha {}",
            listening.0
        );
    }

    #[test]
    fn corners_are_transparent() {
        for state in [State::Off, State::Listening, State::Connected] {
            let icon = render(state);
            assert_eq!(pixel(&icon, 0, 0).0, 0, "top-left must be transparent");
            assert_eq!(
                pixel(&icon, SIZE - 1, SIZE - 1).0,
                0,
                "bottom-right must be transparent"
            );
        }
    }
}
