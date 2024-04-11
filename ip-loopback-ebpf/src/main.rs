#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use core::mem;
use ip_loopback_common::*;
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

const IPPROTO_UDP: u8 = 0x0011;
const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<EthHdr>();
const IP_HDR_LEN: usize = mem::size_of::<Ipv4Hdr>();

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}

#[xdp]
pub fn ip_loopback(ctx: XdpContext) -> u32 {
    match try_ip_loopback(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_ip_loopback(ctx: XdpContext) -> Result<u32, u32> {
    // info!(&ctx, "received a packet");

    let eth = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;

    if unsafe { (*eth).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = ptr_at_mut::<Ipv4Hdr>(&ctx, ETH_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;

    if unsafe { (*ip).proto } != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }

    // Let other unintended packets pass through.
    let udp = ptr_at::<UdpHdr>(&ctx, ETH_HDR_LEN + IP_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { (*udp).dest } != 15000u16.to_be() {
        return Ok(xdp_action::XDP_PASS);
    }

    // NOTE: The words in the packet are already in big-endian,
    // so we need to do a x.to_be() if we want it back to little-endian
    // because our system x86_64 is little-endian and to_le() is a NOOP here.
    unsafe {
        info!(
            &ctx,
            "IPv4 hdr -> ver={} ihl={} tos={} tot_len={} id=0x{:x}",
            (*ip).version(),
            (*ip).ihl(),
            (*ip).tos,
            (*ip).tot_len.to_be(),
            (*ip).id.to_be(),
        );
    }

    let computed_checksum = ipv4_csum::ipv4_checksum_calc(&mut unsafe { *ip }).to_be();
    info!(
        &ctx,
        "IPv4 original checksum: 0x{:x}/0x{:x}",
        unsafe { (*ip).check },
        computed_checksum
    );

    // TODO:
    // Modify the packet:
    // - Swap the source and destination IPv4 addresses.
    // - Swap the source and destination MAC addresses as well,
    //   so that the packet goes to the intended host.
    unsafe {
        info!(&ctx, "Old IPv4 addr 0x{:x} -> 0x{:x}", (*ip).src_addr.to_be(), (*ip).dst_addr.to_be());
        let temp_ip = (*ip).src_addr;
        (*ip).src_addr = (*ip).dst_addr;
        (*ip).dst_addr = temp_ip;
        info!(&ctx, "New IPv4 addr 0x{:x} -> 0x{:x}", (*ip).src_addr.to_be(), (*ip).dst_addr.to_be());

        // Swap src and dst MAC addresses.
        info!(
            &ctx,
            "Old eth addr {:x}:{:x}:{:x}:{:x}:{:x}:{:x} -> {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            (*eth).src_addr[0], (*eth).src_addr[1], (*eth).src_addr[2],
            (*eth).src_addr[3], (*eth).src_addr[4], (*eth).src_addr[5],
            (*eth).dst_addr[0], (*eth).dst_addr[1], (*eth).dst_addr[2],
            (*eth).dst_addr[3], (*eth).dst_addr[4], (*eth).dst_addr[5],
        );
        let temp_addr = (*eth).src_addr;
        (*eth).src_addr = (*eth).dst_addr;
        (*eth).dst_addr = temp_addr;
        info!(
            &ctx,
            "New eth addr {:x}:{:x}:{:x}:{:x}:{:x}:{:x} -> {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            (*eth).src_addr[0], (*eth).src_addr[1], (*eth).src_addr[2],
            (*eth).src_addr[3], (*eth).src_addr[4], (*eth).src_addr[5],
            (*eth).dst_addr[0], (*eth).dst_addr[1], (*eth).dst_addr[2],
            (*eth).dst_addr[3], (*eth).dst_addr[4], (*eth).dst_addr[5],
        );
    }

    info!(&ctx, "Packet modified...updating IP header checksum.");
    let computed_checksum = ipv4_csum::ipv4_checksum_calc(&mut unsafe { *ip }).to_be();
    unsafe {
        (*ip).check = computed_checksum;
    }
    info!(
        &ctx,
        "IPv4 new checksum: 0x{:x}/0x{:x}",
        unsafe { (*ip).check },
        computed_checksum
    );

    Ok(xdp_action::XDP_TX)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
