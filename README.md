# PCAP to JPEG Extractor

A Python tool to extract JPEG images from PCAP files using `tshark`. Useful for simple network forensics and quick inspection of image streams.

## Features

- Extracts JPEG images from TCP streams
- Optional filters: source IP, port, destination, and stream index
- Interactive mode with basic analysis to suggest parameters
- Generates a log file of the extraction process

## Requirements

- Python 3
- [Wireshark](https://www.wireshark.org/) (specifically, `tshark` command-line tool)

Install `tshark` on Debian/Ubuntu:

```bash
sudo apt install tshark
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Installation

Clone the repository:

```bash
git clone https://github.com/cyto0x/pcap-jpeg-extractor.git
cd pcap-jpeg-extractor
```

## Usage

### Basic (interactive):

```bash
python3 pcap_extractor.py -f capture.pcap
```

### With filters:

```bash
python3 pcap_extractor.py -f capture.pcap --src-port 8081 --stream 2
```

### Full control:

```bash
python3 pcap_extractor.py -f capture.pcap \
  --src-ip 192.168.1.10 \
  --dst-ip 10.0.0.5 \
  --src-port 8081 \
  --dst-port 43210 \
  --stream 5
```

### Fully automatic:

```bash
python3 pcap_extractor.py -f capture.pcap --auto
```

Extracted images will be saved in the `extracted_frames/` directory by default.

## Output

- JPEG images: `extracted_frames/frame_00001.jpg`, etc.
- Log file: `pcap_jpeg_extractor.log`

## Limitations

- Works best on unencrypted JPEG streams
- No support for reassembly of fragmented TCP streams
- Detection is based on basic JPEG header markers (JFIF/Exif)
- Not guaranteed to work on heavily obfuscated or complex traffic

## License

MIT License

## Disclaimer

This is a simple forensic helper—not a robust forensic suite. Use it accordingly.

