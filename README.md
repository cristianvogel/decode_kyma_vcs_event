A Rust crate for decoding [Kyma](https://kyma.symbolicsound.com/) *optimised* VCS event blobs, transmitted using [the Kyma OSC protocol](http://www.symbolicsound.com/cgi-bin/bin/view/Learn/OpenSoundControlImplementation).

`/vcs,b` is sent when a value changes on the VCS (for example, when a fader is moved).

__Additional Information:__
The response to a `/osc/widget,i` message is either a `/vcs/widget,is` or `/vcs/widget,ib` depending on whether “Optimize Kyma Control Communication” is turned on in the Performance Preferences in Kyma. The blob response is a gzipped version of the JSON string you would get if the communications were not optimized.

## Features
- Parses `/vcs,b` event packets.
- Handles type tags, blob lengths, and error conditions.


## License
This project is licensed under the MIT OR Apache-2.0 license.
