use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::theme;
use crate::ui;

#[derive(Debug, Clone, Copy)]
pub struct Banner {
    pub name: &'static str,
    pub art: &'static str,
}

impl Banner {
    pub fn width(self) -> u16 {
        art_width(self.art)
    }

    pub fn height(self) -> u16 {
        art_height(self.art)
    }

    pub fn fits_width(self, width: u16) -> bool {
        width >= self.width().saturating_add(2)
    }

    pub fn fits(self, width: u16, height: u16) -> bool {
        self.fits_width(width) && height >= self.height()
    }
}

pub const TEXT: Banner = Banner {
    name: "text",
    art: "AppleUtils",
};

pub const ALL: &[Banner] = &[
    Banner {
        name: "doh",
        art: DOH,
    },
    Banner {
        name: "colossal",
        art: COLOSSAL,
    },
    Banner {
        name: "mini",
        art: MINI,
    },
    Banner {
        name: "soft",
        art: SOFT,
    },
    Banner {
        name: "slant",
        art: SLANT,
    },
    Banner {
        name: "box",
        art: BOX,
    },
    Banner {
        name: "chunky",
        art: CHUNKY,
    },
    Banner {
        name: "shade",
        art: SHADE,
    },
    Banner {
        name: "roman",
        art: ROMAN,
    },
    Banner {
        name: "stars",
        art: STARS,
    },
    Banner {
        name: "heavy",
        art: HEAVY,
    },
    Banner {
        name: "ghost",
        art: GHOST,
    },
    Banner {
        name: "script",
        art: SCRIPT,
    },
];

const DOH: &str = r#"
  /$$$$$$                      /$$           /$$   /$$   /$$     /$$ /$$
 /$$__  $$                    | $$          | $$  | $$  | $$    |__/| $$
| $$  \ $$  /$$$$$$   /$$$$$$ | $$  /$$$$$$ | $$  | $$ /$$$$$$   /$$| $$  /$$$$$$$
| $$$$$$$$ /$$__  $$ /$$__  $$| $$ /$$__  $$| $$  | $$|_  $$_/  | $$| $$ /$$_____/
| $$__  $$| $$  \ $$| $$  \ $$| $$| $$$$$$$$| $$  | $$  | $$    | $$| $$|  $$$$$$
| $$  | $$| $$  | $$| $$  | $$| $$| $$_____/| $$  | $$  | $$ /$$| $$| $$ \____  $$
| $$  | $$| $$$$$$$/| $$$$$$$/| $$|  $$$$$$$|  $$$$$$/  |  $$$$/| $$| $$ /$$$$$$$/
|__/  |__/| $$____/ | $$____/ |__/ \_______/ \______/    \___/  |__/|__/|_______/
          | $$      | $$
          | $$      | $$
          |__/      |__/
"#;

const COLOSSAL: &str = r#"
_____/\\\\\\\\\_________________________________/\\\\\\____________________/\\\________/\\\______________________/\\\\\\_________________
 ___/\\\\\\\\\\\\\______________________________\////\\\___________________\/\\\_______\/\\\_____________________\////\\\_________________
  __/\\\/////////\\\___/\\\\\\\\\____/\\\\\\\\\_____\/\\\___________________\/\\\_______\/\\\_____/\\\_______/\\\____\/\\\_________________
   _\/\\\_______\/\\\__/\\\/////\\\__/\\\/////\\\____\/\\\________/\\\\\\\\__\/\\\_______\/\\\__/\\\\\\\\\\\_\///_____\/\\\_____/\\\\\\\\\\_
    _\/\\\\\\\\\\\\\\\_\/\\\\\\\\\\__\/\\\\\\\\\\_____\/\\\______/\\\/////\\\_\/\\\_______\/\\\_\////\\\////___/\\\____\/\\\____\/\\\//////__
     _\/\\\/////////\\\_\/\\\//////___\/\\\//////______\/\\\_____/\\\\\\\\\\\__\/\\\_______\/\\\____\/\\\______\/\\\____\/\\\____\/\\\\\\\\\\_
      _\/\\\_______\/\\\_\/\\\_________\/\\\____________\/\\\____\//\\///////___\//\\\______/\\\_____\/\\\_/\\__\/\\\____\/\\\____\////////\\\_
       _\/\\\_______\/\\\_\/\\\_________\/\\\__________/\\\\\\\\\__\//\\\\\\\\\\__\///\\\\\\\\\/______\//\\\\\___\/\\\__/\\\\\\\\\__/\\\\\\\\\\_
        _\///________\///__\///__________\///__________\/////////____\//////////_____\/////////_________\/////____\///__\/////////__\//////////__
"#;

const MINI: &str = r#"
 ______     ______   ______   __         ______     __  __     ______   __     __         ______
/\  __ \   /\  == \ /\  == \ /\ \       /\  ___\   /\ \/\ \   /\__  _\ /\ \   /\ \       /\  ___\
\ \  __ \  \ \  _-/ \ \  _-/ \ \ \____  \ \  __\   \ \ \_\ \  \/_/\ \/ \ \ \  \ \ \____  \ \___  \
 \ \_\ \_\  \ \_\    \ \_\    \ \_____\  \ \_____\  \ \_____\    \ \_\  \ \_\  \ \_____\  \/\_____\
  \/_/\/_/   \/_/     \/_/     \/_____/   \/_____/   \/_____/     \/_/   \/_/   \/_____/   \/_____/
"#;

const SOFT: &str = r#"
   ░███                          ░██            ░██     ░██    ░██    ░██░██
  ░██░██                         ░██            ░██     ░██    ░██       ░██
 ░██  ░██  ░████████  ░████████  ░██  ░███████  ░██     ░██ ░████████ ░██░██  ░███████
░█████████ ░██    ░██ ░██    ░██ ░██ ░██    ░██ ░██     ░██    ░██    ░██░██ ░██
░██    ░██ ░██    ░██ ░██    ░██ ░██ ░█████████ ░██     ░██    ░██    ░██░██  ░███████
░██    ░██ ░███   ░██ ░███   ░██ ░██ ░██         ░██   ░██     ░██    ░██░██        ░██
░██    ░██ ░██░█████  ░██░█████  ░██  ░███████    ░██████       ░████ ░██░██  ░███████
           ░██        ░██
           ░██        ░██
"#;

const SLANT: &str = r#"
 ________  ________  ________  ___       _______   ___  ___  _________  ___  ___       ________
|\   __  \|\   __  \|\   __  \|\  \     |\  ___ \ |\  \|\  \|\___   ___\\  \|\  \     |\   ____\
\ \  \|\  \ \  \|\  \ \  \|\  \ \  \    \ \   __/|\ \  \\\  \|___ \  \_\ \  \ \  \    \ \  \___|_
 \ \   __  \ \   ____\ \   ____\ \  \    \ \  \_|/_\ \  \\\  \   \ \  \ \ \  \ \  \    \ \_____  \
  \ \  \ \  \ \  \___|\ \  \___|\ \  \____\ \  \_|\ \ \  \\\  \   \ \  \ \ \  \ \  \____\|____|\  \
   \ \__\ \__\ \__\    \ \__\    \ \_______\ \_______\ \_______\   \ \__\ \ \__\ \_______\____\_\  \
    \|__|\|__|\|__|     \|__|     \|_______|\|_______|\|_______|    \|__|  \|__|\|_______|\_________\
                                                                                         \|_________|
"#;

const BOX: &str = r#"
 █████╗ ██████╗ ██████╗ ██╗     ███████╗██╗   ██╗████████╗██╗██╗     ███████╗
██╔══██╗██╔══██╗██╔══██╗██║     ██╔════╝██║   ██║╚══██╔══╝██║██║     ██╔════╝
███████║██████╔╝██████╔╝██║     █████╗  ██║   ██║   ██║   ██║██║     ███████╗
██╔══██║██╔═══╝ ██╔═══╝ ██║     ██╔══╝  ██║   ██║   ██║   ██║██║     ╚════██║
██║  ██║██║     ██║     ███████╗███████╗╚██████╔╝   ██║   ██║███████╗███████║
╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝╚══════╝╚══════╝
"#;

const CHUNKY: &str = r#"
    ▄▄                         ▄▄▄▄                ▄▄    ▄▄               ██     ▄▄▄▄
   ████                        ▀▀██                ██    ██    ██         ▀▀     ▀▀██
   ████    ██▄███▄   ██▄███▄     ██       ▄████▄   ██    ██  ███████    ████       ██      ▄▄█████▄
  ██  ██   ██▀  ▀██  ██▀  ▀██    ██      ██▄▄▄▄██  ██    ██    ██         ██       ██      ██▄▄▄▄ ▀
  ██████   ██    ██  ██    ██    ██      ██▀▀▀▀▀▀  ██    ██    ██         ██       ██       ▀▀▀▀██▄
 ▄██  ██▄  ███▄▄██▀  ███▄▄██▀    ██▄▄▄   ▀██▄▄▄▄█  ▀██▄▄██▀    ██▄▄▄   ▄▄▄██▄▄▄    ██▄▄▄   █▄▄▄▄▄██
 ▀▀    ▀▀  ██ ▀▀▀    ██ ▀▀▀       ▀▀▀▀     ▀▀▀▀▀     ▀▀▀▀       ▀▀▀▀   ▀▀▀▀▀▀▀▀     ▀▀▀▀    ▀▀▀▀▀▀
           ██        ██
"#;

const SHADE: &str = r#"
   █████████                       ████           █████  █████  █████     ███  ████
  ███▒▒▒▒▒███                     ▒▒███          ▒▒███  ▒▒███  ▒▒███     ▒▒▒  ▒▒███
 ▒███    ▒███  ████████  ████████  ▒███   ██████  ▒███   ▒███  ███████   ████  ▒███   █████
 ▒███████████ ▒▒███▒▒███▒▒███▒▒███ ▒███  ███▒▒███ ▒███   ▒███ ▒▒▒███▒   ▒▒███  ▒███  ███▒▒
 ▒███▒▒▒▒▒███  ▒███ ▒███ ▒███ ▒███ ▒███ ▒███████  ▒███   ▒███   ▒███     ▒███  ▒███ ▒▒█████
 ▒███    ▒███  ▒███ ▒███ ▒███ ▒███ ▒███ ▒███▒▒▒   ▒███   ▒███   ▒███ ███ ▒███  ▒███  ▒▒▒▒███
 █████   █████ ▒███████  ▒███████  █████▒▒██████  ▒▒████████    ▒▒█████  █████ █████ ██████
▒▒▒▒▒   ▒▒▒▒▒  ▒███▒▒▒   ▒███▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒▒    ▒▒▒▒▒▒▒▒      ▒▒▒▒▒  ▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒▒
               ▒███      ▒███
               █████     █████
              ▒▒▒▒▒     ▒▒▒▒▒
"#;

const ROMAN: &str = r#"
    :::     :::::::::  :::::::::  :::        :::::::::: :::    ::: ::::::::::: ::::::::::: :::        ::::::::
  :+: :+:   :+:    :+: :+:    :+: :+:        :+:        :+:    :+:     :+:         :+:     :+:       :+:    :+:
 +:+   +:+  +:+    +:+ +:+    +:+ +:+        +:+        +:+    +:+     +:+         +:+     +:+       +:+
+#++:++#++: +#++:++#+  +#++:++#+  +#+        +#++:++#   +#+    +:+     +#+         +#+     +#+       +#++:++#++
+#+     +#+ +#+        +#+        +#+        +#+        +#+    +#+     +#+         +#+     +#+              +#+
#+#     #+# #+#        #+#        #+#        #+#        #+#    #+#     #+#         #+#     #+#       #+#    #+#
###     ### ###        ###        ########## ##########  ########      ###     ########### ########## ########
"#;

const STARS: &str = r#"
     **                      **         **     **   **   **  **
    ****    ******  ******  /**        /**    /**  /**  //  /**
   **//**  /**///**/**///** /**  ***** /**    /** ****** ** /**  ******
  **  //** /**  /**/**  /** /** **///**/**    /**///**/ /** /** **////
 **********/****** /******  /**/*******/**    /**  /**  /** /**//*****
/**//////**/**///  /**///   /**/**//// /**    /**  /**  /** /** /////**
/**     /**/**     /**      ***//******//*******   //** /** *** ******
//      // //      //      ///  //////  ///////     //  // /// //////
"#;

const HEAVY: &str = r#"
                                                                          ██
   ▒██▒                        ████                ██    ██               ██     ████
   ▓██▓                        ████                ██    ██    ██         ██     ████
   ████                          ██                ██    ██    ██                  ██
   ████    ██░███▒   ██░███▒     ██       ░████▒   ██    ██  ███████    ████       ██       ▒█████░
  ▒█▓▓█▒   ███████▒  ███████▒    ██      ░██████▒  ██    ██  ███████    ████       ██      ████████
  ▓█▒▒█▓   ███  ███  ███  ███    ██      ██▒  ▒██  ██    ██    ██         ██       ██      ██▒  ░▒█
  ██  ██   ██░  ░██  ██░  ░██    ██      ████████  ██    ██    ██         ██       ██      █████▓░
  ██████   ██    ██  ██    ██    ██      ████████  ██    ██    ██         ██       ██      ░██████▒
 ░██████░  ██░  ░██  ██░  ░██    ██      ██        ██    ██    ██         ██       ██         ░▒▓██
 ▒██  ██▒  ███  ███  ███  ███    ██▒     ███░  ▒█  ██▓  ▓██    ██░        ██       ██▒     █▒░  ▒██
 ███  ███  ███████▒  ███████▒    █████   ░███████  ▒██████▒    █████   ████████    █████   ████████
 ██▒  ▒██  ██░███▒   ██░███▒     ░████    ░█████▒   ▒████▒     ░████   ████████    ░████   ░▓████▓
           ██        ██
           ██        ██
           ██        ██
"#;

const GHOST: &str = r#"
   █████████                       ████           █████  █████  █████     ███  ████
  ███░░░░░███                     ░░███          ░░███  ░░███  ░░███     ░░░  ░░███
 ░███    ░███  ████████  ████████  ░███   ██████  ░███   ░███  ███████   ████  ░███   █████
 ░███████████ ░░███░░███░░███░░███ ░███  ███░░███ ░███   ░███ ░░░███░   ░░███  ░███  ███░░
 ░███░░░░░███  ░███ ░███ ░███ ░███ ░███ ░███████  ░███   ░███   ░███     ░███  ░███ ░░█████
 ░███    ░███  ░███ ░███ ░███ ░███ ░███ ░███░░░   ░███   ░███   ░███ ███ ░███  ░███  ░░░░███
 █████   █████ ░███████  ░███████  █████░░██████  ░░████████    ░░█████  █████ █████ ██████
░░░░░   ░░░░░  ░███░░░   ░███░░░  ░░░░░  ░░░░░░    ░░░░░░░░      ░░░░░  ░░░░░ ░░░░░ ░░░░░░
               ░███      ░███
               █████     █████
              ░░░░░     ░░░░░
"#;

const SCRIPT: &str = r#"
 ______                  ___           __  __  __         ___
/\  _  \                /\_ \         /\ \/\ \/\ \__  __ /\_ \
\ \ \L\ \  _____   _____\//\ \      __\ \ \ \ \ \ ,_\/\_\\//\ \     ____
 \ \  __ \/\ '__`\/\ '__`\\ \ \   /'__`\ \ \ \ \ \ \/\/\ \ \ \ \   /',__\
  \ \ \/\ \ \ \L\ \ \ \L\ \\_\ \_/\  __/\ \ \_\ \ \ \_\ \ \ \_\ \_/\__, `\
   \ \_\ \_\ \ ,__/\ \ ,__//\____\ \____\\ \_____\ \__\\ \_\/\____\/\____/
    \/_/\/_/\ \ \/  \ \ \/ \/____/\/____/ \/_____/\/__/ \/_/\/____/\/___/
             \ \_\   \ \_\
              \/_/    \/_/
"#;

pub const SMALL: &[Banner] = &[
    Banner {
        name: "standard",
        art: STANDARD,
    },
    Banner {
        name: "blocks",
        art: BLOCKS,
    },
    Banner {
        name: "compact",
        art: COMPACT,
    },
    Banner {
        name: "path",
        art: PATH,
    },
    Banner {
        name: "corners",
        art: CORNERS,
    },
    Banner {
        name: "double",
        art: DOUBLE,
    },
    Banner {
        name: "light",
        art: LIGHT,
    },
    Banner {
        name: "mosaic",
        art: MOSAIC,
    },
];

const STANDARD: &str = r#"
                       _      _    _ _   _ _     
     /\               | |    | |  | | | (_) |    
    /  \   _ __  _ __ | | ___| |  | | |_ _| |___ 
   / /\ \ | '_ \| '_ \| |/ _ \ |  | | __| | / __|
  / ____ \| |_) | |_) | |  __/ |__| | |_| | \__ \
 /_/    \_\ .__/| .__/|_|\___|\____/ \__|_|_|___/
          | |   | |                              
          |_|   |_|                              
"#;

const BLOCKS: &str = r#"
 ▗▄▖ ▄▄▄▄  ▄▄▄▄  █ ▗▞▀▚▖▗▖ ▗▖   ■  ▄ █  ▄▄▄ 
▐▌ ▐▌█   █ █   █ █ ▐▛▀▀▘▐▌ ▐▌▗▄▟▙▄▖▄ █ ▀▄▄  
▐▛▀▜▌█▄▄▄▀ █▄▄▄▀ █ ▝▚▄▄▖▐▌ ▐▌  ▐▌  █ █ ▄▄▄▀ 
▐▌ ▐▌█     █     █      ▝▚▄▞▘  ▐▌  █ █      
     ▀     ▀                   ▐▌           
"#;

const COMPACT: &str = r#"
▄▖    ▜   ▖▖▗ ▘▜   
▌▌▛▌▛▌▐ █▌▌▌▜▘▌▐ ▛▘
▛▌▙▌▙▌▐▖▙▖▙▌▐▖▌▐▖▄▌
  ▌ ▌              
"#;

const PATH: &str = r#"
    ___                __     __  ____  _ __    
   /   |  ____  ____  / /__  / / / / /_(_) /____
  / /| | / __ \/ __ \/ / _ \/ / / / __/ / / ___/
 / ___ |/ /_/ / /_/ / /  __/ /_/ / /_/ / (__  ) 
/_/  |_/ .___/ .___/_/\___/\____/\__/_/_/____/  
      /_/   /_/                                 
"#;

const CORNERS: &str = r#"
┏┓    ┓  ┳┳ •┓ 
┣┫┏┓┏┓┃┏┓┃┃╋┓┃┏
┛┗┣┛┣┛┗┗ ┗┛┗┗┗┛
  ┛ ┛          
"#;

const DOUBLE: &str = r#"
╔═╗┌─┐┌─┐┬  ┌─┐╦ ╦┌┬┐┬┬  ┌─┐
╠═╣├─┘├─┘│  ├┤ ║ ║ │ ││  └─┐
╩ ╩┴  ┴  ┴─┘└─┘╚═╝ ┴ ┴┴─┘└─┘
"#;

const LIGHT: &str = r#"
┌─┐┌─┐┌─┐╷  ┌─╴╷ ╷╶┬╴╷╷  ┌─┐
├─┤├─┘├─┘│  ├╴ │ │ │ ││  └─┐
╵ ╵╵  ╵  └─╴└─╴└─┘ ╵ ╵└─╴└─┘
"#;

const MOSAIC: &str = r#"
▞▀▖      ▜    ▌ ▌▐  ▗▜    
▙▄▌▛▀▖▛▀▖▐ ▞▀▖▌ ▌▜▀ ▄▐ ▞▀▘
▌ ▌▙▄▘▙▄▘▐ ▛▀ ▌ ▌▐ ▖▐▐ ▝▀▖
▘ ▘▌  ▌   ▘▝▀▘▝▀  ▀ ▀▘▘▀▀
"#;

#[derive(Debug, Clone)]
pub struct BannerOrder {
    pub large: Vec<usize>,
    pub small: Vec<usize>,
}

impl BannerOrder {
    pub fn shuffled() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        Self {
            large: shuffle_indices(ALL.len(), seed),
            small: shuffle_indices(SMALL.len(), seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)),
        }
    }

    pub fn sequential() -> Self {
        Self {
            large: (0..ALL.len()).collect(),
            small: (0..SMALL.len()).collect(),
        }
    }
}

pub fn art_lines(art: &str) -> Vec<&str> {
    art.lines()
        .map(|line| line.trim_end())
        .filter(|line| !line.is_empty())
        .collect()
}

pub fn art_width(art: &str) -> u16 {
    art_lines(art)
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0) as u16
}

pub fn art_height(art: &str) -> u16 {
    art_lines(art).len() as u16
}

fn shuffle_indices(len: usize, mut seed: u64) -> Vec<usize> {
    let mut order: Vec<usize> = (0..len).collect();
    for i in (1..order.len()).rev() {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let j = (seed as usize) % (i + 1);
        order.swap(i, j);
    }
    order
}

fn first_fit_in(pool: &[Banner], order: &[usize], width: u16, height: u16) -> Option<Banner> {
    order.iter().find_map(|&index| {
        pool.get(index)
            .copied()
            .filter(|banner| banner.fits_width(width) && height >= banner.height())
    })
}

pub fn pick(order: &BannerOrder, width: u16, height: u16) -> Option<Banner> {
    first_fit_in(ALL, &order.large, width, height)
        .or_else(|| first_fit_in(SMALL, &order.small, width, height))
        .or_else(|| TEXT.fits(width, height).then_some(TEXT))
}

pub fn render_art(frame: &mut Frame, area: Rect, art: &str, style: Style) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let lines = art_lines(art);
    let width = lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0) as u16;
    let height = lines.len() as u16;
    let slot = ui::center(area, width.min(area.width), height.min(area.height));
    let text: Vec<Line> = lines
        .into_iter()
        .map(|line| Line::from(line.to_string()).style(style))
        .collect();
    frame.render_widget(Paragraph::new(text), slot);
}

pub fn render_banner(frame: &mut Frame, area: Rect, banner: Banner) {
    if banner.name == TEXT.name {
        render_art(frame, area, banner.art, theme::title());
    } else {
        render_art(frame, area, banner.art, theme::ice());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffle_is_a_permutation() {
        let mut order = BannerOrder::shuffled();
        order.large.sort();
        order.small.sort();
        assert_eq!(order.large, (0..ALL.len()).collect::<Vec<_>>());
        assert_eq!(order.small, (0..SMALL.len()).collect::<Vec<_>>());
    }

    #[test]
    fn first_fit_skips_oversized() {
        let order: Vec<usize> = (0..ALL.len()).collect();
        let picked = first_fit_in(ALL, &order, 80, 8);
        assert!(picked.is_some());
        assert!(picked.unwrap().fits(80, 8));
        assert!(first_fit_in(ALL, &order, 40, 3).is_none());
    }

    #[test]
    fn first_fit_skips_too_wide_even_when_height_fits() {
        let colossal = ALL.iter().position(|banner| banner.name == "colossal");
        let stars = ALL.iter().position(|banner| banner.name == "stars");
        let order = vec![colossal.unwrap(), stars.unwrap()];
        let picked = first_fit_in(ALL, &order, 80, 20).expect("stars fits 80 columns");
        assert_eq!(picked.name, "stars");
        assert!(picked.fits_width(80));
        assert!(first_fit_in(ALL, &order, 70, 20).is_none());
    }

    #[test]
    fn pick_uses_small_pool_when_large_are_too_wide() {
        let order = BannerOrder::sequential();
        assert!(ALL.iter().all(|banner| !banner.fits_width(60)));
        let picked = pick(&order, 60, 8).expect("a small banner should fit");
        assert!(SMALL.iter().any(|banner| banner.name == picked.name));
        assert!(picked.fits_width(60));
    }

    #[test]
    fn pick_falls_back_to_all_caps_when_no_art_fits_width() {
        let order = BannerOrder::sequential();
        let picked = pick(&order, 16, 8).expect("AppleUtils text fits");
        assert_eq!(picked.name, TEXT.name);
        assert_eq!(picked.art, "AppleUtils");
        assert!(ALL.iter().all(|banner| !banner.fits_width(16)));
        assert!(SMALL.iter().all(|banner| !banner.fits_width(16)));
    }

    #[test]
    fn all_say_apple_or_utils_shape() {
        assert_eq!(ALL.len(), 13);
        for banner in ALL {
            assert!(banner.width() > 40);
            assert!(banner.height() >= 4);
        }
        assert_eq!(SMALL.len(), 8);
        for banner in SMALL {
            assert!(banner.width() > 10);
            assert!(banner.height() >= 3);
            assert!(banner.width() < ALL.iter().map(|large| large.width()).min().unwrap());
        }
    }
}
