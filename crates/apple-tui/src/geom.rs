use ratatui::layout::Rect;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlateClass {
    Card,
    Wait,
    Session,
}

impl PlateClass {
    pub fn max_w(self) -> u16 {
        match self {
            PlateClass::Card => 56,
            PlateClass::Wait => 50,
            PlateClass::Session => 58,
        }
    }

    pub fn min_w(self) -> u16 {
        match self {
            PlateClass::Card => 40,
            PlateClass::Wait => 36,
            PlateClass::Session => 50,
        }
    }

    pub fn min_h(self) -> u16 {
        match self {
            PlateClass::Card => 8,
            PlateClass::Wait => 7,
            PlateClass::Session => 16,
        }
    }
}

pub fn inset(area: Rect, pad_x: u16, pad_y: u16) -> Rect {
    let pad_x = pad_x.min(area.width / 2);
    let pad_y = pad_y.min(area.height / 2);
    Rect {
        x: area.x + pad_x,
        y: area.y + pad_y,
        width: area.width.saturating_sub(pad_x * 2),
        height: area.height.saturating_sub(pad_y * 2),
    }
}

pub fn center(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

pub fn plate(area: Rect, max_w: u16, min_w: u16, height: u16) -> Rect {
    let inner = area.width.saturating_sub(4);
    let width = inner.clamp(min_w.min(inner), max_w.min(inner).max(min_w.min(inner)));
    let height = height.min(area.height.saturating_sub(1)).max(3);
    center(area, width, height)
}

pub fn plate_class(area: Rect, class: PlateClass, height: u16) -> Rect {
    let height = height
        .min(area.height.saturating_sub(1))
        .max(class.min_h().min(area.height.saturating_sub(1)).max(3));
    plate(area, class.max_w(), class.min_w(), height)
}

pub fn contains_rect(outer: Rect, inner: Rect) -> bool {
    if inner.width == 0 || inner.height == 0 {
        return inner.x >= outer.x
            && inner.y >= outer.y
            && inner.x <= outer.x.saturating_add(outer.width)
            && inner.y <= outer.y.saturating_add(outer.height);
    }
    let right = inner.x.saturating_add(inner.width);
    let bottom = inner.y.saturating_add(inner.height);
    inner.x >= outer.x
        && inner.y >= outer.y
        && right <= outer.x.saturating_add(outer.width)
        && bottom <= outer.y.saturating_add(outer.height)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inset_center_and_plate_class_stay_in_bounds() {
        let area = Rect::new(4, 2, 80, 24);
        let samples = [
            inset(area, 4, 2),
            center(area, 20, 5),
            plate(area, 56, 40, 11),
            plate_class(area, PlateClass::Card, 11),
            plate_class(area, PlateClass::Wait, 9),
            plate_class(area, PlateClass::Session, 20),
        ];
        for inner in samples {
            assert!(
                contains_rect(area, inner),
                "out of bounds: {inner:?} in {area:?}"
            );
            assert!(inner.width > 0 && inner.height > 0);
        }

        let tight = Rect::new(1, 1, 12, 8);
        let card = plate_class(tight, PlateClass::Card, 11);
        assert!(contains_rect(tight, card), "{card:?} vs {tight:?}");
        assert!(card.width > 0 && card.height > 0);
        assert!(card.width <= tight.width);
        assert!(card.height <= tight.height);
    }
}
