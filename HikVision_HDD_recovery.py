#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HIKVISION DVR RAW FILESYSTEM RECOVERY TOOL
Author: MiniBotScripts (with assistance from AI tool: Gemini)
License: MIT - This software is provided 'as is', without warranty of any kind !
Date: 02-09-2025
Version: 0.2 (Parallel Search)
"""

import sys
import argparse
import struct
import os
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

# --- Global Settings ---
DEBUG_MODE = False
DEFAULT_BLOCK_SIZE = 1073741824  # 1 GiB

def log_debug(message):
    if DEBUG_MODE:
        print(f"[DEBUG] {message}", file=sys.stderr)

def format_size(size_bytes):
    if size_bytes <= 0: return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    import math
    try:
        if size_bytes < 1024: return f"{size_bytes} B"
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_name[i]}"
    except (ValueError, IndexError):
        return f"{size_bytes} B"

class BlockDeviceHandler:
    def __init__(self, device_path):
        self.device_path = device_path # Store path for worker threads
        try:
            # Main thread opens a handle to get initial info
            self.device = open(device_path, "rb")
        except FileNotFoundError:
            print(f"Error: Device or file '{device_path}' not found.", file=sys.stderr)
            sys.exit(1)
        except PermissionError:
            print(f"Error: Permission denied for '{device_path}'. Run with admin/sudo privileges.", file=sys.stderr)
            sys.exit(1)

    def close(self):
        if self.device:
            self.device.close()

class HikvisionParser:
    def __init__(self, handler):
        self.handler = handler
        self.master_sector = {}
        self.btree = {}

    def _parse_master_sector(self):
        """Parses the Hikvision Master Sector."""
        self.handler.device.seek(528)
        sig_bytes = self.handler.device.read(32)
        signature = sig_bytes.decode('ascii', errors='ignore').strip('\x00')
        if "HIKVISION" not in signature: raise ValueError("Hikvision signature not found.")
        self.master_sector['signature'] = signature
        self.handler.device.read(24)
        self.master_sector['hdd_cap'] = struct.unpack('<Q', self.handler.device.read(8))[0]
        self.handler.device.read(16); self.handler.device.read(8); self.handler.device.read(8); self.handler.device.read(8)
        self.master_sector['video_data_area_offset'] = struct.unpack('<Q', self.handler.device.read(8))[0]
        self.handler.device.read(8)
        self.master_sector['data_block_size'] = struct.unpack('<Q', self.handler.device.read(8))[0]
        self.master_sector['data_block_total'] = struct.unpack('<I', self.handler.device.read(4))[0]
        self.handler.device.read(4) # PADDING
        self.master_sector['hikbtree1_offset'] = struct.unpack('<Q', self.handler.device.read(8))[0]
        self.handler.device.read(76)
        self.master_sector['init_time'] = struct.unpack('<I', self.handler.device.read(4))[0]

    def _parse_btree(self):
        """Parses the B-Tree header to find the page list."""
        btree_offset = self.master_sector.get('hikbtree1_offset', 0)
        if not btree_offset: raise ValueError("B-Tree offset is zero.")

        self.handler.device.seek(btree_offset)
        self.handler.device.read(16)
        self.btree['signature'] = self.handler.device.read(8).decode('ascii', errors='ignore')
        self.handler.device.read(56)
        self.btree['page_list_offset'] = struct.unpack('<Q', self.handler.device.read(8))[0]

    def get_data_page_offsets(self, force=False):
        """Returns a list of offsets to data pages that need to be scanned."""
        self._parse_master_sector()
        self._parse_btree()

        page_list_offset = self.btree.get('page_list_offset')
        if not page_list_offset: raise ValueError("Page list offset is zero.")

        self.handler.device.seek(page_list_offset)
        self.handler.device.read(96)

        data_pages_offsets = []
        while True:
            entry_data = self.handler.device.read(40)
            if not entry_data or len(entry_data) < 40: break
            page_offset = struct.unpack_from('<Q', entry_data, 0)[0]

            if page_offset == 0 or page_offset == 0xFFFFFFFFFFFFFFFF: break

            data_pages_offsets.append(page_offset)
        return data_pages_offsets

def scan_data_page(device_path, page_offset, hdd_capacity, block_size, force, results_queue, write_lock):
    """
    Worker function executed in a thread. Scans a single data page for file entries.
    Each thread opens its own file handle to the device.
    """
    try:
        with open(device_path, "rb") as device_handle:
            if not force and page_offset > hdd_capacity:
                return

            device_handle.seek(page_offset)
            device_handle.read(96)

            while True:
                entry_data = device_handle.read(40)
                if not entry_data or len(entry_data) < 40: break

                existence_marker = struct.unpack_from('<Q', entry_data, 8)[0]
                if existence_marker != 0: continue

                channel = struct.unpack_from('>H', entry_data, 16)[0]
                start_time_ts = struct.unpack_from('<I', entry_data, 24)[0]
                end_time_ts = struct.unpack_from('<I', entry_data, 28)[0]
                data_offset = struct.unpack_from('<Q', entry_data, 32)[0]

                if start_time_ts == 0 or data_offset == 0: continue

                if not force and hdd_capacity > 0 and (data_offset + block_size) > hdd_capacity:
                    continue

                try:
                    start_dt = datetime.fromtimestamp(start_time_ts)
                    end_dt = datetime.fromtimestamp(end_time_ts)
                except (OSError, ValueError): continue

                # Wait here if a write operation is in progress
                with write_lock:
                    results_queue.put({
                        'channel': channel, 'start_time': start_dt, 'end_time': end_dt,
                        'data_offset': data_offset
                    })
    except Exception as e:
        log_debug(f"Error in worker thread for page offset {page_offset}: {e}")

def extract_single_file(device_path, output_path, offset, size):
    """Extracts a single file. Used by the main thread."""
    try:
        # This function also needs its own handle as the main one is closed
        with open(device_path, "rb") as handler, open(output_path, "wb") as dest_file:
            handler.seek(offset)
            bytes_remaining = size
            buffer_size = 1024 * 1024
            while bytes_remaining > 0:
                chunk = handler.read(min(buffer_size, bytes_remaining))
                if not chunk:
                    print(f"\nWarning: End of device reached while reading.", file=sys.stderr)
                    break
                dest_file.write(chunk)
                bytes_remaining -= len(chunk)
        return True
    except Exception as e:
        print(f"\nERROR during recovery of '{output_path}': {e}", file=sys.stderr, flush=True)
        return False

def main():
    parser = argparse.ArgumentParser(
        description="List and recover video files from a Hikvision formatted block device.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Author: MiniBotScripts (with assistance from AI tool: Gemini)
License: MIT - This software is provided 'as is', without warranty of any kind !
Version: 0.2 (Parallel Search)

Examples:
  1. List all files (standard channels only):
     sudo python3 %(prog)s /dev/sdb

  2. Recover all standard files (faster search, sequential writing):
     sudo python3 %(prog)s /dev/sdb -o ./recovered_videos

  3. Recover a single file by offset:
     sudo python3 %(prog)s /dev/sdb -o clip.mp4 --recover-offset 0x746E0084C00
"""
    )
    # --- Arguments ---
    parser.add_argument("device", help="Path to the block device or disk image (e.g., /dev/sdb).")
    parser.add_argument("-o", "--output-dir", help="Output target. Directory for full scan or file path for single recovery.", default=None)
    parser.add_argument("--recover-offset", help="Recover a single file from a specific offset. Requires -o.", default=None)
    parser.add_argument("--block-size", type=int, help="Override auto-detected block size. Use with --recover-offset.", default=None)
    parser.add_argument("--show-all-channels", action="store_true", help="Display files from channel 0 and channels > 32.")
    parser.add_argument("--force", action="store_true", help="Force listing/recovery of files with out-of-bounds offsets.")
    parser.add_argument("--debug", action="store_true", help="Enable detailed diagnostic logging.")

    args = parser.parse_args()

    global DEBUG_MODE
    if args.debug:
        DEBUG_MODE = True
        print("--- DEBUG MODE ENABLED ---", file=sys.stderr)

    handler = None
    try:
        # Main handler is only for initial parsing
        handler = BlockDeviceHandler(args.device)
        hik_parser = HikvisionParser(handler)

        # --- Single File Recovery Mode ---
        if args.recover_offset:
            # Code for single file recovery remains the same
            if not args.output_dir:
                parser.error("--recover-offset requires -o <output_file>.")
            offset = int(args.recover_offset, 0)

            block_size_to_use = 0
            if args.block_size:
                block_size_to_use = args.block_size
            else:
                try:
                    hik_parser._parse_master_sector()
                    block_size_to_use = hik_parser.master_sector.get('data_block_size', DEFAULT_BLOCK_SIZE)
                except (ValueError, struct.error):
                    block_size_to_use = DEFAULT_BLOCK_SIZE
                    print(f"Warning: Could not detect block size. Using default: {format_size(block_size_to_use)}", file=sys.stderr)

            print(f"Attempting single file recovery...")
            if extract_single_file(handler.device_path, args.output_dir, offset, block_size_to_use):
                print("Recovery successful.")
            else:
                print("Recovery failed.")
            return

        # --- Parallel Full Scan Mode ---
        print("Starting initial scan to find data pages...")
        data_page_offsets = hik_parser.get_data_page_offsets(force=args.force)

        if not data_page_offsets:
            print("Scan complete. No data pages found.", file=sys.stderr)
            return

        print(f"Found {len(data_page_offsets)} data pages to scan. Starting parallel search...")

        print("-" * 85)
        print(f"{'Start Time':<22} | {'Ch':^5} | {'Offset (Hex)':<18} | {'Offset (Decimal)':<20} | {'Size':^8}")
        print("-" * 85)

        results_queue = Queue()
        write_lock = threading.Lock() # Lock to pause workers during a write
        num_workers = min(os.cpu_count() or 4, 32)

        hdd_capacity = hik_parser.master_sector.get('hdd_cap', 0)
        block_size = hik_parser.master_sector.get('data_block_size', 0)
        block_size_str = format_size(block_size)

        # Use a context manager for the thread pool
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            # Submit all scan jobs
            for page_offset in data_page_offsets:
                executor.submit(scan_data_page, handler.device_path, page_offset, hdd_capacity, block_size, args.force, results_queue, write_lock)

            found_files_count = 0
            # Poll the queue for results until all pages are processed
            processed_pages = 0
            while processed_pages < len(data_page_offsets):
                if not results_queue.empty():
                    file_info = results_queue.get()

                    if (file_info['channel'] > 32 or file_info['channel'] == 0) and not args.show_all_channels:
                        continue

                    found_files_count += 1
                    start_dt, end_dt = file_info['start_time'], file_info['end_time']
                    offset = file_info['data_offset']
                    start_str = start_dt.strftime('%Y-%m-%d %H:%M:%S')
                    print(f"{start_str:<22} | {file_info['channel']:^5} | 0x{offset:<16X} | {offset:<20} | {block_size_str:>8}", flush=True)

                    if args.output_dir:
                        # Acquire lock, pausing all worker threads
                        with write_lock:
                            os.makedirs(args.output_dir, exist_ok=True)
                            filename = (f"{start_dt.strftime('%Y-%m-%d_%H-%M-%S')}-"
                                        f"{end_dt.strftime('%H-%M-%S')}_"
                                        f"ch{file_info['channel']:02d}.mp4")
                            file_path = os.path.join(args.output_dir, filename)
                            print(f"  -> Extracting to {filename}...", end="", flush=True)
                            if extract_single_file(handler.device_path, file_path, offset, block_size):
                                print(" Done.", flush=True)
                            else:
                                print(" FAILED.", flush=True)
                        # Lock is automatically released here, workers can resume

                    results_queue.task_done()
                else:
                    # Check if threads are still alive
                    if executor._shutdown:
                        processed_pages = len(data_page_offsets) # End loop if pool is shutdown
                    else:
                        # Quick sleep to prevent busy-waiting
                        import time
                        time.sleep(0.1)

                # A simple way to track completion
                # In a more complex scenario, one might use futures or a sentinel value in the queue
                if executor._work_queue.qsize() == 0 and results_queue.empty():
                     processed_pages = len(data_page_offsets)

        print("-" * 85)
        if found_files_count > 0:
            print(f"Scan complete. Found {found_files_count} potential video files.")
        else:
            print("Scan complete. No video files found.")

    except (ValueError, struct.error, OSError) as e:
        print(f"\nCritical Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(1)
    finally:
        if handler:
            handler.close()
            print("\n--- Finished ---")

if __name__ == "__main__":
    main()
