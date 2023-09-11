use std::time::Duration;

pub fn parse_iso8601_duration(duration_str: &str) -> Option<Duration> {
    // Create a default `Duration` object to accumulate the duration components.
    let mut duration = Duration::default();

    // Create a buffer to hold the numerical part of the duration components.
    let mut num_buf = String::new();

    // Iterate over the characters in the duration string.
    for ch in duration_str.chars() {
        if ch.is_ascii_digit() {
            // If the character is a digit, add it to the number buffer.
            num_buf.push(ch);
        } else if !num_buf.is_empty() {
            /*
                If the character is not a digit and the number buffer is not empty, then it
                must contain the numerical part of a duration component, so parse it and add
                it to the accumulated duration.
            */
            match ch {
                'y' | 'Y' => {
                    let years = num_buf.parse::<u64>().ok()?; // Try to parse the number buffer as a u64.
                    duration += Duration::from_secs(years * 31536000); // Add the years to the duration (in seconds).
                    num_buf.clear(); // Clear the number buffer for the next component.
                }
                'w' | 'W' => {
                    let weeks = num_buf.parse::<u64>().ok()?;
                    duration += Duration::from_secs(weeks * 604800);
                    num_buf.clear();
                }
                'm' | 'M' => {
                    let months = num_buf.parse::<u64>().ok()?;
                    duration += Duration::from_secs(months * (31536000 / 12));
                    num_buf.clear();
                }
                'd' | 'D' => {
                    let days = num_buf.parse::<u64>().ok()?;
                    duration += Duration::from_secs(days * 86400);
                    num_buf.clear();
                }
                'h' | 'H' => {
                    let hours = num_buf.parse::<u64>().ok()?;
                    duration += Duration::from_secs(hours * 3600);
                    num_buf.clear();
                }
                's' | 'S' => {
                    let seconds = num_buf.parse::<u64>().ok()?;
                    duration += Duration::from_secs(seconds);
                    num_buf.clear()
                }
                _ => return None,
            }
        }
    }

    if !num_buf.is_empty() {
        return None;
    }

    // return the accumulated duration.
    Some(duration)
}

#[test]
fn test_parse_iso8601_duration() {
    assert_eq!(
        parse_iso8601_duration("1H"),
        Some(Duration::from_secs(3600))
    );
    assert_eq!(
        parse_iso8601_duration("2Y1D"),
        Some(Duration::from_secs(63158400))
    );
    assert_eq!(parse_iso8601_duration("Y"), Some(Duration::from_nanos(0)));
}
