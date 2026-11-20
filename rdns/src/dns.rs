pub const SERVFAIL: u8 = 2;
pub const NXDOMAIN: u8 = 3;

const MAX_LABELS: usize = 128;

pub struct Reply {
    pub id: u16,
    pub code: u8,
    pub truncated: bool,
    pub question: String,
    pub names: Vec<String>,
}

pub fn reverse_name(octets: &[u8]) -> String {
    let labels: Vec<String> = octets.iter().rev().map(u8::to_string).collect();
    format!("{}.in-addr.arpa", labels.join("."))
}

pub fn encode(id: u16, name: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(name.len() + 29);
    packet.extend(id.to_be_bytes());
    packet.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, 1]);

    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend(label.as_bytes());
    }

    packet.extend([0, 0, 12, 0, 1]);
    packet.extend([0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    packet
}

pub fn decode(packet: &[u8]) -> Option<Reply> {
    let header = packet.get(..12)?;
    let answers = u16::from_be_bytes([header[6], header[7]]) as usize;
    let (question, end) = read_name(packet, 12)?;
    let names = pointer_names(packet, end + 4, answers);

    Some(Reply {
        id: u16::from_be_bytes([header[0], header[1]]),
        code: header[3] & 15,
        truncated: header[2] & 2 != 0 || names.is_none(),
        question,
        names: names.unwrap_or_default(),
    })
}

fn pointer_names(
    packet: &[u8],
    mut position: usize,
    answers: usize,
) -> Option<Vec<String>> {
    let mut names = Vec::new();

    for _ in 0..answers {
        let (_, end) = read_name(packet, position)?;
        let fixed = packet.get(end..end + 10)?;
        if fixed[..2] == [0, 12] {
            names.push(read_name(packet, end + 10)?.0);
        }
        position = end + 10 + u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
    }
    Some(names)
}

fn read_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut position = start;
    let mut end = None;

    for _ in 0..MAX_LABELS {
        let length = *packet.get(position)? as usize;
        if length == 0 {
            return Some((name, end.unwrap_or(position + 1)));
        }
        if length >= 0xC0 {
            end.get_or_insert(position + 2);
            position = (length & 0x3F) << 8 | *packet.get(position + 1)? as usize;
            continue;
        }

        if !name.is_empty() {
            name.push('.');
        }
        let label = packet.get(position + 1..position + 1 + length)?;
        label.iter().for_each(|&byte| push_escaped(&mut name, byte));
        position += 1 + length;
    }
    None
}

fn push_escaped(name: &mut String, byte: u8) {
    if byte.is_ascii_graphic() && byte != b'.' && byte != b'\\' {
        name.push(byte.to_ascii_lowercase() as char);
    } else {
        name.push_str(&format!("\\{byte:03}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_round_trips_as_question() {
        let name = reverse_name(&[8, 8, 4, 4]);
        let reply = decode(&encode(7, &name)).unwrap();

        assert_eq!(name, "4.4.8.8.in-addr.arpa");
        assert_eq!((reply.id, reply.question, reply.names.len()), (7, name, 0));
    }

    #[test]
    fn compressed_pointer_answer_is_decoded() {
        let mut packet = encode(1, "1.in-addr.arpa");
        packet.truncate(packet.len() - 11);
        packet[2..8].copy_from_slice(&[0x81, 0x83, 0, 1, 0, 1]);
        packet[11] = 0;
        packet.extend([0xC0, 12, 0, 12, 0, 1, 0, 0, 0, 9, 0, 7]);
        packet.extend(*b"\x04Ho\tt\xC0\x0E");
        let reply = decode(&packet).unwrap();

        assert_eq!((reply.code, reply.truncated), (NXDOMAIN, false));
        assert_eq!(reply.names, ["ho\\009t.in-addr.arpa"]);
    }

    #[test]
    fn cut_answer_counts_as_truncated() {
        let mut packet = encode(1, "1.in-addr.arpa");
        packet[7] = 2;

        assert!(decode(&packet).unwrap().truncated);
        assert!(decode(&packet[..9]).is_none());
    }
}
