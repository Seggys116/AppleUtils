use ratatui::Frame;
use ratatui::layout::Rect;

use crate::app::{App, Screen, Tool};
use crate::banner::{self, Banner};
use crate::ui;

#[derive(Debug, Clone, Copy)]
pub struct PickerLayout {
    pub banner: Option<(Rect, Banner)>,
    pub cards: [Rect; 4],
}

pub fn layout(area: Rect, order: &banner::BannerOrder) -> PickerLayout {
    let pad_x = edge_x(area.width);
    let pad_y = edge_y(area.height);
    let inner = ui::inset(area, pad_x, pad_y);

    let n = Tool::ALL.len() as u16;
    let card_h = if inner.height >= n * 5 { 4 } else { 3 };
    let card_gap = u16::from(inner.height >= n * 6);
    let cards_h = card_h * n + card_gap * n.saturating_sub(1);
    let card_w = inner
        .width
        .saturating_sub(2)
        .min(56)
        .max(36.min(inner.width));

    let leftover = inner.height.saturating_sub(cards_h.saturating_add(2));
    let banner = banner::pick(order, inner.width, leftover);

    let banner_h = banner.map(Banner::height).unwrap_or(0);
    let gap = if banner.is_some() {
        if inner.height >= 30 { 2 } else { 1 }
    } else {
        0
    };
    let group_h = banner_h + gap + cards_h;
    let group = ui::center(inner, inner.width, group_h.min(inner.height));

    let mut y = group.y;
    let banner_rect = banner.map(|size| {
        let rect = Rect {
            x: group.x,
            y,
            width: group.width,
            height: size.height().min(group.height),
        };
        y = y.saturating_add(rect.height + gap);
        (rect, size)
    });

    let remain = group
        .y
        .saturating_add(group.height)
        .saturating_sub(y)
        .max(1);
    let mut cards = [Rect::default(); 4];
    let card_x = group.x + group.width.saturating_sub(card_w) / 2;
    let mut cy = y;
    for slot in &mut cards {
        let height = card_h.min(remain.saturating_sub(cy.saturating_sub(y)).max(1));
        *slot = Rect {
            x: card_x,
            y: cy,
            width: card_w.min(group.width),
            height,
        };
        cy = cy.saturating_add(card_h + card_gap);
    }

    PickerLayout {
        banner: banner_rect,
        cards,
    }
}

fn edge_x(width: u16) -> u16 {
    if width >= 120 {
        4
    } else if width >= 90 {
        3
    } else if width >= 70 {
        2
    } else {
        1
    }
}

fn edge_y(height: u16) -> u16 {
    if height >= 40 { 2 } else { 1 }
}

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    if app.screen != Screen::Picker {
        return;
    }

    let plan = layout(area, &app.banner_order);
    app.hits.cards = plan.cards;

    if let Some((rect, size)) = plan.banner {
        banner::render_banner(frame, rect, size);
    }
    for (i, (tool, rect)) in Tool::ALL.iter().zip(plan.cards).enumerate() {
        if rect.width > 0 && rect.height > 0 {
            ui::render_choice_card(frame, rect, tool.name(), tool.blurb(), i == app.selected);
        }
    }
}
