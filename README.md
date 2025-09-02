
# Hikvision DVR Raw Filesystem Recovery Tool

---

## 🚨 Experimental Software Notice 🚨

This tool is experimental and was developed based on reverse-engineering the filesystem from a specific DVR model. It is provided "as is" without any guarantees, warranties, or support. **Do not rely on this tool for critical forensic or data recovery tasks.**

While it has been shown to work on certain drives, it may not be compatible with all Hikvision firmware versions or models. Always work on a bit-for-bit disk image, not the original evidence drive.

---

## 1. Compatibility

This tool has been confirmed to work with a DVR filesystem that presents the following header structure at the beginning of the disk. You can check your drive using a command like:

```bash
sudo hexdump -C /dev/sdX | head -n 20
```

The key identifier is the **`HIKVISION@HANGZHOU`** signature located at offset `0x210`.

**Example Hexdump:**

```bash
$ hexdump -C /dev/sda
00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000200  b4 22 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |."..............|
00000210  48 49 4b 56 49 53 49 4f  4e 40 48 41 4e 47 5a 48  |HIKVISION@HANGZH|
00000220  4f 55 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |OU..............|
00000230  48 49 4b 2e 32 30 31 31  2e 30 33 2e 30 38 00 00  |HIK.2011.03.08..|
```

---

## 2. Features

* Scans raw block devices (e.g., `/dev/sdb`) or disk image files (e.g., `image.dd`).
* **Full Scan Mode**: Lists all recoverable video files with metadata.
* **Single File Recovery Mode**: Recovers a single file by offset (block size auto-detected).
* Optionally extracts all found video files to a specified directory.
* **Safety Checks**: Ignores corrupt/invalid entries by default.
* **Advanced Switches**: Override safety checks for damaged filesystems.
* Processes data on-the-fly with low memory usage.

---

## 3. Requirements

* Python 3.x

---

## 4. Disclaimer

**USE THIS SCRIPT AT YOUR OWN RISK.**
This tool performs low-level read operations. Although designed to be read-only, using the wrong device path can cause data loss.

* Work on a bit-for-bit disk image (e.g., via `dd`), not the original disk.
* The author is not responsible for any damage or data loss.

---

## 5. Usage

Run the script from the command line (requires admin/root rights).

**General Syntax:**

```bash
python3 HikVision_HDD_recovery.py <device_path> [options]
```

### Arguments:

* `device_path` (Required): Raw device or image file path.

  * Linux: `/dev/sdb` (not `/dev/sdb1`)
  * Windows: `\\.\PhysicalDrive1`

### Options:

* `-o, --output-dir <path>` → Output path (dir/file depending on mode).
* `--recover-offset <offset>` → Recover single file by offset (hex or decimal).
* `--block-size <bytes>` → Override auto-detected block size.
* `--show-all-channels` → Show files from channel 0 or >32.
* `--force` → Disable safety checks (use with caution).
* `--debug` → Enable verbose logs.

---

## 6. Examples

### 6.1 List All Files (Safe Mode)

```bash
sudo python3 HikVision_HDD_recovery.py /dev/sdb
```

Windows:

```bash
python HikVision_HDD_recovery.py \\.\PhysicalDrive1
```

**Example Output:**

```
-------------------------------------------------------------------------------------
Start Time             |  Ch   | Offset (Hex)       | Offset (Decimal)     | Size
-------------------------------------------------------------------------------------
2023-10-27 11:05:32    |   1   | 0x746E0084C00      | 8000852364288        |   1.0 GB
2023-10-27 11:06:15    |   2   | 0x746E00C4C00      | 8000852757504        |   1.0 GB
...
```

### 6.2 List All Files (Including Corrupt)

```bash
sudo python3 HikVision_HDD_recovery.py /dev/sdb --show-all-channels --force
```

### 6.3 Recover All Standard Files

```bash
sudo python3 HikVision_HDD_recovery.py /dev/sdb -o ./recovered_videos
```

### 6.4 Recover Single File by Offset

```bash
sudo python3 HikVision_HDD_recovery.py /dev/sdb -o ./clip_ch01.mp4 --recover-offset 0x746E0084C00
```

---

## 7. How It Works

1. Seeks to offset 528 bytes → **Master Sector**.
2. Reads metadata: disk capacity, block size, B-Tree location.
3. Jumps to B-Tree → finds **Page List**.
4. Iterates through Page List → finds **Data Pages**.
5. Scans Data Pages → extracts video metadata & offsets.

---

## 8. License

Released under the **MIT License**.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

---

## 9. Author

**MiniBotScripts**
🔗 [https://github.com/MiniBotScripts](https://github.com/MiniBotScripts)
