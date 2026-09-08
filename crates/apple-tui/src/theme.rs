use ratatui::style::{Color, Modifier, Style};

pub const BG: Color = Color::Rgb(18, 18, 18);
pub const SURFACE: Color = Color::Rgb(28, 28, 28);
pub const RAISED: Color = Color::Rgb(38, 38, 38);
pub const HAIRLINE: Color = Color::Rgb(58, 58, 58);
pub const SILVER: Color = Color::Rgb(210, 210, 210);
pub const MUTE: Color = Color::Rgb(138, 138, 138);
pub const DIM: Color = Color::Rgb(88, 88, 88);
pub const ICE: Color = Color::Rgb(142, 200, 224);
pub const ICE_SOFT: Color = Color::Rgb(90, 138, 160);
pub const WAIT: Color = Color::Rgb(224, 176, 112);
pub const WAIT_SOFT: Color = Color::Rgb(160, 124, 76);
pub const PASS: Color = ICE;
pub const FAIL: Color = Color::Rgb(224, 112, 112);

pub fn bg() -> Style {
    Style::new().bg(BG).fg(SILVER)
}

pub fn title() -> Style {
    Style::new().fg(SILVER).add_modifier(Modifier::BOLD)
}

pub fn mute() -> Style {
    Style::new().fg(MUTE)
}

pub fn dim() -> Style {
    Style::new().fg(DIM)
}

pub fn ice() -> Style {
    Style::new().fg(ICE)
}

pub fn ice_bold() -> Style {
    Style::new().fg(ICE).add_modifier(Modifier::BOLD)
}

pub fn wait() -> Style {
    Style::new().fg(WAIT)
}

pub fn pass() -> Style {
    Style::new().fg(PASS).add_modifier(Modifier::BOLD)
}

pub fn fail() -> Style {
    Style::new().fg(FAIL).add_modifier(Modifier::BOLD)
}

pub fn selected_title() -> Style {
    Style::new().fg(SILVER).add_modifier(Modifier::BOLD)
}

pub fn selected_row() -> Style {
    Style::new()
        .fg(SILVER)
        .bg(RAISED)
        .add_modifier(Modifier::BOLD)
}

pub fn focus_row() -> Style {
    Style::new().fg(BG).bg(ICE).add_modifier(Modifier::BOLD)
}

pub fn list_text() -> Style {
    Style::new().fg(SILVER)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rgb(color: Color) -> (u8, u8, u8) {
        match color {
            Color::Rgb(r, g, b) => (r, g, b),
            other => panic!("expected rgb, got {other:?}"),
        }
    }

    #[test]
    fn graphite_channels_are_equal() {
        for color in [BG, SURFACE, RAISED, HAIRLINE, SILVER, MUTE, DIM] {
            let (r, g, b) = rgb(color);
            assert_eq!(r, g, "{color:?} is not grey");
            assert_eq!(g, b, "{color:?} is not grey");
        }
    }

    #[test]
    fn ice_is_not_used_as_the_page_background() {
        assert_ne!(BG, ICE);
        assert_ne!(SURFACE, ICE);
        assert_ne!(RAISED, ICE);
    }
}
