#[allow(unused)]
use network_types::ip::*;

use crate::csum_core::checksum;

///
/// Checksum is calculated on the following combined byte sequence:
///
///
pub fn ipv4_checksum_calc(ip_hdr: &mut Ipv4Hdr) -> u16 {
    // Set checksum to 0, since we are computing the checksum freshly.
    ip_hdr.check = 0u16;

    // FIXME: This is a shortcut but the EBPF verifier rejects it.
    // let combined_bytes: [u8; Ipv4Hdr::LEN] = unsafe { core::mem::transmute_copy(&ip_hdr) };

    // Deserializing the Ipv4Hdr struct into an array of bytes.
    let mut combined_bytes = [0u8; Ipv4Hdr::LEN];
    combined_bytes[0] = ip_hdr.ihl();
    combined_bytes[0] |= (ip_hdr.version() << 4) & 0xf0;
    combined_bytes[1] = ip_hdr.tos;
    // NOTE: to_le() is a NOOP in little-endian system.
    combined_bytes[2..4].copy_from_slice(&ip_hdr.tot_len.to_le_bytes());
    combined_bytes[4..6].copy_from_slice(&ip_hdr.id.to_le_bytes());
    combined_bytes[6..8].copy_from_slice(&ip_hdr.frag_off.to_le_bytes());
    combined_bytes[8] = ip_hdr.ttl;
    combined_bytes[9] = ip_hdr.proto as u8;
    // header checksum is already zeroe'd, so skip it.
    combined_bytes[12..16].copy_from_slice(&ip_hdr.src_addr.to_le_bytes());
    combined_bytes[16..20].copy_from_slice(&ip_hdr.dst_addr.to_le_bytes());
    // for b in combined_bytes {
    //     info!(ctx, "{:x}", b);
    // }
    checksum(&[&combined_bytes])
}
