//! Tray icons, drawn in code rather than looked up in the icon theme.
//!
//! A themed icon name is only as good as the theme the user happens to have;
//! a missing name means a missing tray icon, which for this application would
//! mean no visible indication that someone else is on the desktop. Drawing the
//! glyph ourselves makes the indicator unconditional.
//!
//! Four states are distinguished by **shape as well as colour**, so the two
//! that matter most - whether anyone is connected, and whether they can type -
//! are still readable without colour discrimination.

use crate::ipc::{AccessMode, State, Status};

/// Tray icons are requested at 22px by most hosts; 24 divides more cleanly.
const SIZE: i32 = 24;

/// What the tray is currently telling the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Indicator {
    /// Nobody has access.
    Off,
    /// A peer is authorised but has not connected yet.
    Waiting,
    /// Connected, view only: they can see but not type.
    Watching,
    /// Connected with keyboard and pointer control.
    Controlling,
}

impl Indicator {
    pub fn from_status(status: &Status) -> Self {
        match (status.state, status.mode) {
            (State::Off, _) => Indicator::Off,
            (State::Listening, _) => Indicator::Waiting,
            (State::Connected, Some(AccessMode::ViewOnly)) => Indicator::Watching,
            (State::Connected, _) => Indicator::Controlling,
        }
    }

    /// True while another person is on the desktop, in either mode.
    pub fn is_connected(self) -> bool {
        matches!(self, Indicator::Watching | Indicator::Controlling)
    }

    /// Colour as 0xRRGGBB. Chosen to differ in brightness as well as hue.
    fn colour(self) -> u32 {
        match self {
            Indicator::Off => 0x9a_a0_a6,         // grey
            Indicator::Waiting => 0xf5_a6_23,     // amber
            Indicator::Watching => 0x42_8f_f5,    // blue
            Indicator::Controlling => 0xe5_39_35, // red
        }
    }

    fn fill(self) -> Fill {
        match self {
            // Nobody is connected: an empty screen.
            Indicator::Off | Indicator::Waiting => Fill::Hollow,
            // Someone is looking: an eye in the middle of the screen.
            Indicator::Watching => Fill::Dot,
            // Someone is driving: the screen is solid.
            Indicator::Controlling => Fill::Solid,
        }
    }
}

/// How the interior of the monitor glyph is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fill {
    Hollow,
    Dot,
    Solid,
}

/// Render the tray glyph for `indicator`.
pub fn render(indicator: Indicator) -> ksni::Icon {
    ksni::Icon {
        width: SIZE,
        height: SIZE,
        data: draw(SIZE, indicator.colour(), indicator.fill()),
    }
}

/// Produce ARGB32 pixels in network byte order, i.e. `[A, R, G, B]`.
fn draw(size: i32, colour: u32, fill: Fill) -> Vec<u8> {
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

    // Centre of the screen area, for the "watching" dot.
    let cx = (left + right) / 2;
    let cy = (top + bottom) / 2;
    let dot_radius_sq = 9; // a 3px-radius disc

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
            let in_dot = {
                let (dx, dy) = (x - cx, y - cy);
                dx * dx + dy * dy <= dot_radius_sq
            };

            let solid_interior = in_screen
                && !in_screen_border
                && match fill {
                    Fill::Solid => true,
                    Fill::Dot => in_dot,
                    Fill::Hollow => false,
                };

            let alpha: u8 = if in_screen_border || in_neck || in_foot || solid_interior {
                0xff
            } else if in_screen {
                0x3a // a wash, so the glyph still reads as a screen
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

    const ALL: [Indicator; 4] = [
        Indicator::Off,
        Indicator::Waiting,
        Indicator::Watching,
        Indicator::Controlling,
    ];

    fn pixel(icon: &ksni::Icon, x: i32, y: i32) -> (u8, u8, u8, u8) {
        let i = ((y * icon.width + x) * 4) as usize;
        (
            icon.data[i],
            icon.data[i + 1],
            icon.data[i + 2],
            icon.data[i + 3],
        )
    }

    fn status(state: State, mode: Option<AccessMode>) -> Status {
        Status {
            state,
            peer: Some("mike".into()),
            cidr: Some("10.0.0.3/32".into()),
            listen: Some("10.0.0.10:5900".into()),
            connections: if state == State::Connected { 1 } else { 0 },
            mode,
            expires_in_seconds: None,
        }
    }

    #[test]
    fn icons_are_well_formed_argb32() {
        for indicator in ALL {
            let icon = render(indicator);
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
            ALL.into_iter().map(Indicator::colour).collect();
        assert_eq!(colours.len(), 4, "states must be visually distinguishable");
    }

    #[test]
    fn every_state_renders_differently() {
        // Colour alone is not enough - someone who cannot separate the hues
        // must still be able to tell these apart.
        let rendered: Vec<Vec<u8>> = ALL.into_iter().map(|i| render(i).data).collect();
        for a in 0..rendered.len() {
            for b in (a + 1)..rendered.len() {
                assert_ne!(
                    rendered[a], rendered[b],
                    "{:?} and {:?} render identically",
                    ALL[a], ALL[b]
                );
            }
        }
    }

    #[test]
    fn the_three_fill_styles_are_distinct_by_shape() {
        // Compare only the alpha channel, which is what carries shape.
        let shape =
            |i: Indicator| -> Vec<u8> { render(i).data.chunks(4).map(|px| px[0]).collect() };
        assert_eq!(
            shape(Indicator::Off),
            shape(Indicator::Waiting),
            "off and waiting share a shape and differ by colour alone"
        );
        assert_ne!(shape(Indicator::Waiting), shape(Indicator::Watching));
        assert_ne!(shape(Indicator::Watching), shape(Indicator::Controlling));
        assert_ne!(shape(Indicator::Off), shape(Indicator::Controlling));
    }

    #[test]
    fn watching_marks_the_centre_but_does_not_fill_the_screen() {
        let icon = render(Indicator::Watching);
        let centre = pixel(&icon, SIZE / 2, (3 + SIZE - 8) / 2);
        assert_eq!(centre.0, 0xff, "the centre dot should be opaque");
        // A point inside the screen but away from the dot stays a wash.
        let off_centre = pixel(&icon, 4, 5);
        assert!(
            off_centre.0 > 0 && off_centre.0 < 0xff,
            "the rest of the screen should stay a wash, got alpha {}",
            off_centre.0
        );
    }

    #[test]
    fn controlling_fills_the_whole_screen() {
        let icon = render(Indicator::Controlling);
        for (x, y) in [(SIZE / 2, (3 + SIZE - 8) / 2), (4, 5), (SIZE - 4, SIZE - 9)] {
            assert_eq!(
                pixel(&icon, x, y).0,
                0xff,
                "({x},{y}) should be solid when someone has control"
            );
        }
    }

    #[test]
    fn state_colour_reaches_the_pixels() {
        let icon = render(Indicator::Controlling);
        let (a, r, g, b) = pixel(&icon, SIZE / 2, 4);
        assert_eq!(a, 0xff, "the outline must be fully opaque");
        assert_eq!((r, g, b), (0xe5, 0x39, 0x35));
    }

    #[test]
    fn corners_are_transparent() {
        for indicator in ALL {
            let icon = render(indicator);
            assert_eq!(pixel(&icon, 0, 0).0, 0, "top-left must be transparent");
            assert_eq!(
                pixel(&icon, SIZE - 1, SIZE - 1).0,
                0,
                "bottom-right must be transparent"
            );
        }
    }

    #[test]
    fn the_indicator_follows_the_daemon_state() {
        assert_eq!(Indicator::from_status(&Status::off()), Indicator::Off);
        assert_eq!(
            Indicator::from_status(&status(State::Listening, Some(AccessMode::Control))),
            Indicator::Waiting
        );
        assert_eq!(
            Indicator::from_status(&status(State::Connected, Some(AccessMode::ViewOnly))),
            Indicator::Watching
        );
        assert_eq!(
            Indicator::from_status(&status(State::Connected, Some(AccessMode::Control))),
            Indicator::Controlling
        );
    }

    #[test]
    fn an_unknown_mode_is_treated_as_control() {
        // Fail towards the louder indication: if we cannot tell, assume the
        // peer can type rather than quietly implying they cannot.
        assert_eq!(
            Indicator::from_status(&status(State::Connected, None)),
            Indicator::Controlling
        );
    }

    #[test]
    fn both_connected_states_count_as_connected() {
        assert!(Indicator::Watching.is_connected());
        assert!(Indicator::Controlling.is_connected());
        assert!(!Indicator::Off.is_connected());
        assert!(!Indicator::Waiting.is_connected());
    }
}
