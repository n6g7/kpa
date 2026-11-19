//! `ext-data-control-v1` and `zwlr-data-control-v1`, behind one interface.
//!
//! Both let a client with no surface and no keyboard focus own the
//! clipboard, which is the only way a daemon can. They're the same protocol
//! under two names: `ext` is the standardized one, `zwlr` what older
//! compositors still offer. `ext` is preferred when a compositor has both.
//! Only the regular clipboard is used, so version 1 of either is enough.

use wayland_client::globals::GlobalList;
use wayland_client::protocol::wl_seat::WlSeat;
use wayland_client::{Connection, Dispatch, Proxy, QueueHandle, event_created_child};
use wayland_protocols::ext::data_control::v1::client::{
    ext_data_control_device_v1 as ext_device, ext_data_control_manager_v1 as ext_manager,
    ext_data_control_offer_v1 as ext_offer, ext_data_control_source_v1 as ext_source,
};
use wayland_protocols_wlr::data_control::v1::client::{
    zwlr_data_control_device_v1 as zwlr_device, zwlr_data_control_manager_v1 as zwlr_manager,
    zwlr_data_control_offer_v1 as zwlr_offer, zwlr_data_control_source_v1 as zwlr_source,
};

use super::copy::State;

pub enum Manager {
    Ext(ext_manager::ExtDataControlManagerV1),
    Zwlr(zwlr_manager::ZwlrDataControlManagerV1),
}

pub enum Device {
    Ext(ext_device::ExtDataControlDeviceV1),
    Zwlr(zwlr_device::ZwlrDataControlDeviceV1),
}

pub enum Source {
    Ext(ext_source::ExtDataControlSourceV1),
    Zwlr(zwlr_source::ZwlrDataControlSourceV1),
}

impl Manager {
    /// The compositor's data-control manager, `None` if it has neither.
    pub fn bind(globals: &GlobalList, qh: &QueueHandle<State>) -> Option<Manager> {
        globals
            .bind(qh, 1..=1, ())
            .map(Manager::Ext)
            .or_else(|_| globals.bind(qh, 1..=1, ()).map(Manager::Zwlr))
            .ok()
    }

    pub fn get_data_device(&self, seat: &WlSeat, qh: &QueueHandle<State>) -> Device {
        match self {
            Manager::Ext(m) => Device::Ext(m.get_data_device(seat, qh, ())),
            Manager::Zwlr(m) => Device::Zwlr(m.get_data_device(seat, qh, ())),
        }
    }

    pub fn create_data_source(&self, qh: &QueueHandle<State>) -> Source {
        match self {
            Manager::Ext(m) => Source::Ext(m.create_data_source(qh, ())),
            Manager::Zwlr(m) => Source::Zwlr(m.create_data_source(qh, ())),
        }
    }
}

impl Device {
    /// Makes `source` the seat's clipboard selection. `Device` and `Source`
    /// always come from the same `Manager`, so their families match.
    pub fn set_selection(&self, source: &Source) {
        match (self, source) {
            (Device::Ext(d), Source::Ext(s)) => d.set_selection(Some(s)),
            (Device::Zwlr(d), Source::Zwlr(s)) => d.set_selection(Some(s)),
            _ => unreachable!("a device and a source from different managers"),
        }
    }

    pub fn destroy(&self) {
        match self {
            Device::Ext(d) => d.destroy(),
            Device::Zwlr(d) => d.destroy(),
        }
    }
}

impl Source {
    pub fn offer(&self, mime_type: &str) {
        match self {
            Source::Ext(s) => s.offer(mime_type.to_string()),
            Source::Zwlr(s) => s.offer(mime_type.to_string()),
        }
    }

    pub fn destroy(&self) {
        match self {
            Source::Ext(s) => s.destroy(),
            Source::Zwlr(s) => s.destroy(),
        }
    }

    /// False once destroyed, by kpa or after the compositor cancelled it.
    pub fn is_alive(&self) -> bool {
        match self {
            Source::Ext(s) => s.is_alive(),
            Source::Zwlr(s) => s.is_alive(),
        }
    }
}

/// The same `Dispatch` impls for both families, whose event enums have the
/// same variants under different types.
macro_rules! impl_family {
    (
        $manager:ident::$Manager:ident,
        $device:ident::$Device:ident,
        $offer:ident::$Offer:ident,
        $source:ident::$Source:ident
    ) => {
        impl Dispatch<$manager::$Manager, ()> for State {
            fn event(
                _: &mut State,
                _: &$manager::$Manager,
                _: $manager::Event,
                _: &(),
                _: &Connection,
                _: &QueueHandle<State>,
            ) {
            }
        }

        impl Dispatch<$device::$Device, ()> for State {
            fn event(
                _: &mut State,
                device: &$device::$Device,
                event: $device::Event,
                _: &(),
                _: &Connection,
                _: &QueueHandle<State>,
            ) {
                match event {
                    // Every selection change, kpa's own included, arrives as
                    // a new offer. kpa never pastes, so it never reads one.
                    $device::Event::DataOffer { id } => id.destroy(),
                    $device::Event::Finished => device.destroy(),
                    _ => {}
                }
            }

            event_created_child!(State, $device::$Device, [
                $device::EVT_DATA_OFFER_OPCODE => ($offer::$Offer, ()),
            ]);
        }

        impl Dispatch<$offer::$Offer, ()> for State {
            fn event(
                _: &mut State,
                _: &$offer::$Offer,
                _: $offer::Event,
                _: &(),
                _: &Connection,
                _: &QueueHandle<State>,
            ) {
            }
        }

        impl Dispatch<$source::$Source, ()> for State {
            fn event(
                state: &mut State,
                source: &$source::$Source,
                event: $source::Event,
                _: &(),
                _: &Connection,
                _: &QueueHandle<State>,
            ) {
                match event {
                    $source::Event::Send { mime_type, fd } => state.send(&mime_type, fd),
                    // Something else took the clipboard.
                    $source::Event::Cancelled => source.destroy(),
                    _ => {}
                }
            }
        }
    };
}

impl_family!(
    ext_manager::ExtDataControlManagerV1,
    ext_device::ExtDataControlDeviceV1,
    ext_offer::ExtDataControlOfferV1,
    ext_source::ExtDataControlSourceV1
);
impl_family!(
    zwlr_manager::ZwlrDataControlManagerV1,
    zwlr_device::ZwlrDataControlDeviceV1,
    zwlr_offer::ZwlrDataControlOfferV1,
    zwlr_source::ZwlrDataControlSourceV1
);
