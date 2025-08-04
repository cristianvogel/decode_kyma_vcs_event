A Rust crate for decoding [Kyma](https://kyma.symbolicsound.com/) *optimised* VCS event blobs, transmitted using [the Kyma OSC protocol](http://www.symbolicsound.com/cgi-bin/bin/view/Learn/OpenSoundControlImplementation).

`/vcs,b` is sent when a value changes on the VCS (for example, when a fader is moved).

## Features
- Parses `/vcs,b` event packets.
- Handles type tags, blob lengths, and error conditions.


## License
This project is licensed under the MIT OR Apache-2.0 license.