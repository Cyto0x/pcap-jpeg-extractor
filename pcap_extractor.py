#!/usr/bin/env python3
"""
Ultimate Configurable PCAP to JPEG Extraction Tool
Author: Cyber Security Enthusiast
Date: 2023-10-15
"""
import os
import sys
import argparse
import subprocess
import binascii
import logging
import re
import readline  # For better input handling

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('pcap_jpeg_extractor.log')
    ]
)
logger = logging.getLogger('pcap_jpeg_extractor')

def get_user_input(prompt, default=None):
    """Get user input with default value support"""
    if default:
        full_prompt = f"{prompt} [{default}]: "
    else:
        full_prompt = f"{prompt}: "
    
    try:
        user_input = input(full_prompt).strip()
        return user_input if user_input else default
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)

def analyze_pcap(pcap_file):
    """Analyze PCAP file and suggest extraction parameters"""
    logger.info(f"Analyzing {pcap_file}...")
    
    # Get top conversations
    try:
        conv_result = subprocess.run(
            ["tshark", "-r", pcap_file, "-q", "-z", "conv,tcp"],
            capture_output=True,
            text=True
        )
        top_conversations = []
        for line in conv_result.stdout.split('\n'):
            if '<->' in line and '192.' in line:
                parts = line.split()
                if len(parts) > 4:
                    stream_id = parts[0]
                    bytes_transferred = parts[4]
                    top_conversations.append((stream_id, bytes_transferred))
        
        # Get HTTP info
        http_result = subprocess.run(
            ["tshark", "-r", pcap_file, "-Y", "http", "-T", "fields", "-e", "http.host", "-e", "http.content_type"],
            capture_output=True,
            text=True
        )
        http_info = http_result.stdout
        
        # Find potential image ports
        image_ports = set()
        jpeg_result = subprocess.run(
            ["tshark", "-r", pcap_file, "-Y", "frame contains \"JFIF\"", "-T", "fields", "-e", "tcp.srcport"],
            capture_output=True,
            text=True
        )
        for port in jpeg_result.stdout.split():
            if port.strip():
                image_ports.add(port.strip())
        
        return {
            "top_conversations": top_conversations[:3],  # Top 3
            "http_info": http_info,
            "image_ports": list(image_ports)
        }
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        return None

def extract_jpegs(pcap_file, output_dir, src_port=None, dst_port=None, 
                 src_ip=None, dst_ip=None, stream_id=None):
    """Extract JPEGs based on specified parameters"""
    # Build tshark filter
    filters = ["tcp"]
    
    if src_port:
        filters.append(f"tcp.srcport == {src_port}")
    if dst_port:
        filters.append(f"tcp.dstport == {dst_port}")
    if src_ip:
        filters.append(f"ip.src == {src_ip}")
    if dst_ip:
        filters.append(f"ip.dst == {dst_ip}")
    if stream_id is not None:
        filters.append(f"tcp.stream == {stream_id}")
    
    display_filter = " and ".join(filters)
    
    logger.info(f"Using filter: {display_filter}")
    
    # Step 1: Extract TCP payloads as hex
    hex_file = os.path.join(output_dir, "payload.hex")
    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", display_filter,
        "-T", "fields", "-e", "tcp.payload"
    ]
    logger.info("Extracting payloads...")
    with open(hex_file, 'w') as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE)
    
    # Step 2: Clean hex data
    logger.info("Cleaning hex data...")
    clean_hex = ""
    with open(hex_file, 'r') as f:
        for line in f:
            clean_line = ''.join(c for c in line.strip() if c in '0123456789abcdefABCDEF')
            if clean_line:
                clean_hex += clean_line
    
    if not clean_hex:
        logger.error("No valid hex data found")
        return 0
    
    # Step 3: Convert to binary
    logger.info("Converting to binary...")
    try:
        # Handle odd-length hex strings
        if len(clean_hex) % 2 != 0:
            clean_hex = clean_hex[:-1]
        binary_data = binascii.unhexlify(clean_hex)
    except binascii.Error as e:
        logger.error(f"Hex conversion failed: {str(e)}")
        return 0
    
    # Step 4: Extract JPEGs
    logger.info("Scanning for JPEGs...")
    
    # Find all JPEG start markers
    jpg_starts = [m.start() for m in re.finditer(b'\xff\xd8', binary_data)]
    
    if not jpg_starts:
        logger.warning("No JPEG start markers found")
        return 0
    
    # Find all JPEG end markers
    jpg_ends = [m.start() + 2 for m in re.finditer(b'\xff\xd9', binary_data)]
    
    # Extract valid JPEGs
    extracted_count = 0
    for i, start in enumerate(jpg_starts):
        # Find the next end marker after this start
        end = next((e for e in jpg_ends if e > start and e - start < 5000000), None)
        
        if end:
            jpg_data = binary_data[start:end]
            # Basic validation: check for JFIF/Exif in header
            if b'JFIF' in jpg_data[:100] or b'Exif' in jpg_data[:100]:
                output_file = os.path.join(output_dir, f"frame_{extracted_count+1:05d}.jpg")
                with open(output_file, 'wb') as f:
                    f.write(jpg_data)
                extracted_count += 1
                if extracted_count % 100 == 0:
                    logger.info(f"Extracted frame {extracted_count}")
    
    return extracted_count

def main():
    parser = argparse.ArgumentParser(
        description="Configurable PCAP to JPEG Extraction Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-f", "--file", required=True, help="PCAP file to analyze")
    parser.add_argument("-o", "--output", default="extracted_frames", 
                        help="Output directory for JPEGs")
    parser.add_argument("--src-port", help="Source port (server port for responses)")
    parser.add_argument("--dst-port", help="Destination port (client port)")
    parser.add_argument("--src-ip", help="Source IP address")
    parser.add_argument("--dst-ip", help="Destination IP address")
    parser.add_argument("--stream", type=int, help="TCP stream index")
    parser.add_argument("--auto", action="store_true", 
                        help="Attempt automatic extraction without prompts")
    args = parser.parse_args()
    
    if not os.path.isfile(args.file):
        logger.error(f"PCAP file not found: {args.file}")
        sys.exit(1)
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Analyze PCAP if running in interactive mode
    if not (args.src_port or args.dst_port or args.src_ip or args.dst_ip or args.stream) and not args.auto:
        analysis = analyze_pcap(args.file)
        
        if analysis:
            print("\n=== PCAP Analysis Results ===")
            if analysis.get('top_conversations'):
                print("\nTop TCP Conversations:")
                for stream_id, bytes_transferred in analysis['top_conversations']:
                    print(f"  Stream {stream_id}: {bytes_transferred} bytes")
            
            if analysis.get('image_ports'):
                print("\nPorts with JPEG Traffic:")
                for port in analysis['image_ports']:
                    print(f"  Port {port}")
            
            if analysis.get('http_info'):
                print("\nHTTP Information:")
                print(analysis['http_info'][:500] + ("..." if len(analysis['http_info']) > 500 else ""))
            
            print("\n")
    
    # Get parameters from user if not provided
    if not args.src_port and not args.auto:
        suggested_port = analysis.get('image_ports', [None])[0] if analysis else None
        args.src_port = get_user_input("Enter server port (where images come from)", suggested_port)
    
    if not args.stream and not args.auto:
        suggested_stream = analysis.get('top_conversations', [[None]])[0][0] if analysis else None
        args.stream = get_user_input("Enter TCP stream index (or leave blank)", suggested_stream)
        try:
            args.stream = int(args.stream) if args.stream else None
        except ValueError:
            logger.error("Invalid stream index, ignoring")
            args.stream = None
    
    # Run extraction
    try:
        frame_count = extract_jpegs(
            args.file,
            args.output,
            src_port=args.src_port,
            dst_port=args.dst_port,
            src_ip=args.src_ip,
            dst_ip=args.dst_ip,
            stream_id=args.stream
        )
        
        if frame_count > 0:
            logger.info(f"Success! Extracted {frame_count} JPEG frames to {args.output}")
            sys.exit(0)
        else:
            logger.error("No JPEGs extracted. Possible reasons:")
            logger.error("1. Incorrect filter parameters")
            logger.error("2. PCAP doesn't contain JPEG images")
            logger.error("3. Images are in unexpected format")
            logger.error("4. Packets are fragmented or encrypted")
            sys.exit(1)
    except Exception as e:
        logger.exception("Critical error during extraction")
        sys.exit(1)

if __name__ == "__main__":
    main()
