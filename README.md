# 🔬 Digital Forensics Case Study: WESMANTOOTH-PC

A full Windows disk forensic examination of the **Mantooth.E01** practice evidence image, from evidence verification through registry analysis, web history reconstruction, and media and document review, ending in an evidence-based conclusion.

> **Scenario:** The suspect, Wes Mantooth, is alleged to have committed **credit card skimming fraud** and to have possessed or attempted to manufacture **illegal drugs**. The goal is to establish **who used the computer** and whether the evidence on it **supports or fails to support** those allegations.
>
> *This is a fictional subject in a widely used forensic training image. No real person is involved.*

| | |
|---|---|
| **Evidence** | `Mantooth.E01` (EnCase E01, 250,879 sectors × 512 bytes = 122.5 MB) |
| **System** | Windows, hostname `WESMANTOOTH-PC`, OS installed 2007-02-27 |
| **Tools** | Magnet AXIOM 9.10 · Forensic Explorer 5.6.8 · AccessData FTK Imager (acquisition) |
| **Time standard** | All timestamps UTC |
| **Full report** | [`report/Mantooth_Forensic_Report.pdf`](report/) *(add your PDF here)* |

---

## 📑 Contents
1. [Evidence Integrity](#1-evidence-integrity)
2. [Methodology](#2-methodology)
3. [User Attribution (SAM)](#3-user-attribution-sam-hive)
4. [System & Software Hives](#4-system--software-hives)
5. [User Activity (NTUSER.DAT)](#5-user-activity-ntuserdat)
6. [Disk Structure](#6-disk-structure)
7. [Web Activity Timeline](#7-web-activity-timeline)
8. [Media, Email Attachments & Documents](#8-media-email-attachments--documents)
9. [Conclusion](#9-conclusion)
10. [Limitations & Recommendations](#10-limitations--recommendations)

---

## 1. Evidence Integrity

Before any analysis, I verified that the image hadn't been altered since acquisition.

| Item | Value |
|---|---|
| Acquired with | AccessData FTK Imager 2.5.3.14 (Windows XP host) |
| Acquisition date | 2008-07-02 21:09:34 UTC |
| Format / compression | EnCase E01, fast compression |
| **MD5 (acquisition)** | `31217210a1a69f272079a3bde3d9d8fc` |
| **MD5 (verification)** | `31217210a1a69f272079a3bde3d9d8fc` ✅ **match** |
| SHA-1 (computed) | `12e4ac047e328ca2bd63a4d65df25b3ecba55769` |
| SHA-256 (computed) | `735ec4d84551ad31585ac346fc90a53d0730f8637e77c4cdc8ac9ff37c77ca7b` |

Only MD5 was recorded at acquisition, so I computed SHA-1 and SHA-256 at intake to establish stronger hashes for the rest of the examination.

## 2. Methodology

```
Verify hashes ──► Create case (time zone set) ──► Evidence processing
                                                    (MBR + file system search, signature analysis)
      │
      ├─► Registry analysis   SAM · SYSTEM · SOFTWARE · NTUSER.DAT      (Forensic Explorer)
      ├─► Disk structure      partitions, file systems                (AXIOM)
      └─► Artifact review     web history · media · email · documents  (AXIOM)
                │
                ▼
      Correlate timestamps across sources ──► Conclusion
```

**Time zones matter:** the case was configured so registry timestamps (Forensic Explorer) and artifact timestamps (AXIOM) are both reported in **UTC**. That's what made the cross-tool timeline in section 7 reliable.

## 3. User Attribution (SAM hive)

`Windows\System32\config\SAM` → `SAM\Domains\Account\Users`

| Account | RID | Created (UTC) | Logins | Last login (UTC) | Notes |
|---|---|---|---|---|---|
| Administrator | 500 | 2007-02-27 | 1 | 2006-11-02 | Disabled, built-in |
| Guest | 501 | 2007-02-27 | 0 | never | Disabled, built-in |
| **Wes Mantooth** | **1000** | 2007-02-27 | **96** | **2008-02-12 19:12:08** | Password hint *"in your face"*, 3 failed attempts |
| Dracula | 1002 | 2007-03-06 | 3 | 2007-04-02 00:30:58 | Full name "Count Dracula", comment "The Tooth Account" |
| Laurent | 1003 | 2008-02-12 00:13:36 | 0 | never | No password required |

**Finding:** the only other account ever used (Dracula) **stopped logging in before** the relevant activity (July–August 2007), and every artifact below lives under the **Wes Mantooth** profile. That attributes the activity to his account.

## 4. System & Software Hives

**SYSTEM** (`ControlSet001` / `ControlSet003`)
- Computer name **`WESMANTOOTH-PC`** in both control sets
- **15 USB storage devices** in `Enum\USBSTOR`, most with *Last User: Wes Mantooth*

| Device | Drive | Last connected (MountPoints2, UTC) |
|---|---|---|
| Apple iPod | G: | 2008-02-12 17:21:52 |
| Flash Drive UT_USB20 | F: | 2008-02-12 19:19:30 |
| Flash Drive UT_USB20 (2nd) | n/a | 2008-02-12 20:50:15 |
| TREK TD2SMART G3M | n/a | 2008-02-12 16:48:34 |
| SanDisk Cruzer Mini | E: | 2007-10-11 21:33:18 |
| Sony DSC (digital camera) | H: | 2007-04-13 00:52:17 |
| + 2× Maxtor external HDDs, more flash drives & TREK ThumbDrives | | |

**SOFTWARE**
- OS install date **2007-02-27 19:22:03**, the same day the accounts were created, so no user activity should predate it
- Registered owner **Wes Mantooth**, organization **Volturi Enterprises**
- Mail clients registered: AOL, Hotmail, Outlook, Windows Mail, Yahoo! Mail
- **26 installed programs**. The ones relevant to the case:

| Category | Programs | Why it matters |
|---|---|---|
| 🔐 Encryption | **BestCrypt 8.0**, **TrueCrypt** | Evidence could be hidden in encrypted containers |
| 📤 Transfer / remote | FileZilla (FTP), VNC Free Edition, P2P Networking, WinRAR | Data could have been moved off the system |
| 💬 Communication | AIM 6, Trillian, Yahoo! Messenger, Windows Live Messenger | Possible co-conspirator contact |
| 🧰 Forensic tools | FTK Imager, Registry Viewer, DNA | Suspect knew forensic techniques, suggesting anti-forensic awareness |

## 5. User Activity (NTUSER.DAT)

`Users\Wes Mantooth\NTUSER.DAT` → `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

| Type | Items of interest |
|---|---|
| **Files** | `ATM_THEFTS1.ppt` · `CC Nums.xls` · `Those who owes.xls` · `C money plates.doc` |
| **Folders** | `Checks` · `Car Titles` · `Business Ideas` · `Scripts` · `Secret Stuff` · `Super Secret Stuff` · `Tooth Docs` · `EFS DOCS` |
| **Images** | `Prescription2.gif` · `prescription.gif` · `doc-prescription.jpg` · `untitled.bmp` · `Guts.bmp` · `Camera.bmp` |
| **Encryption** | Text files named like **BitLocker keys**, plus a **`BESTCRYPT.EXE` prefetch** file, which shows the encryption tool was actually *run* |

Several of these were opened from **Removable Disk E: and F:**, which matches the USB devices in section 4. Those devices were **not part of this image**.

## 6. Disk Structure

| Partition | Size | File system |
|---|---|---|
| 1 | 109.79 MB | NTFS |
| 2 | 7.84 MB | EXT-family |
| + unpartitioned space | | |

## 7. Web Activity Timeline

AXIOM recovered **999 web artifacts** (195 Google searches, 121 IE history records, 26 rebuilt web pages) from
`Users\Wes Mantooth\AppData\Local\Microsoft\Windows\History\History.IE5\index.dat`.

**2007-07-12 (UTC): a 16-minute window**

| Time | Event |
|---|---|
| 23:13 | Visits Snopes pages about a **hidden ATM camera** |
| 23:14–23:15 | Opens `untitled.bmp`, `Guts.bmp`, `Camera.bmp` from **`E:\Business Ideas`** |
| 23:15:24 | Surveillance-style "CAM 2" image cached |
| **23:15:34** | Google search: **"atm card stealing"** |
| 23:15:52 | Visits a drug "recipes" page (rebuilt by AXIOM) |
| **23:16:01** | Google search: **"making meth"** |
| 23:16:03–23:16:19 | Visits two more drug-manufacturing pages (rebuilt by AXIOM) |
| 23:16:44 | Photo of numbered supplies (`images[9].jpg`) created |
| 23:17 | Google search: **"check washing"** · drug and paraphernalia images cached |
| 23:28 | Opens `ATM_THEFTS1.ppt` (Desktop) |
| 23:29:42 | Opens `E:\Business Ideas\ATM_THEFTS1.ppt` (opened 3×, **recovered by carving**) |

**2007-08-05:** webmail and IM activity (AIM Express, Yahoo, AOL, Gmail), plus searches for *"I am searching for bad stuff"* on Google, Yahoo, and other engines.

> The strongest evidence is **temporal correlation**: searches, page visits, cached images, and local files opened from removable media all fall within minutes of each other under the same user profile.

## 8. Media, Email Attachments & Documents

**Media:** 546 pictures, 2 videos

| Category | Evidence |
|---|---|
| **Check fraud** | Blank check templates with placeholder names · `Check1.png` ($1,950.50) · `scan1.jpg`, a scanned **$8,000 cashier's check**, created **one second after** `Check1.png`, so the two were saved or scanned together |
| **Vehicle fraud** | Scan resembling a **NJ DMV vehicle title** (matches the `Car Titles` folder) |
| **ATM skimming** | Photos of an ATM with a **brochure holder** (a common hidden-camera spot) · surveillance-camera frame |
| **Drugs** | Supplies photo created mid-search · barbiturate and paraphernalia images · `Prescription2.gif` in `Documents\Scripts`, a **prescription template** with a generic "John Doe MD" |

**Email attachments (23):** prescription forms, ATM photos, and an **opened device with a battery and wiring**. The same themes, now in email, suggest the material was **shared with someone else**.

**Documents (84):**
- IE cookies show visits to **TrueCrypt** and **Evidence Washer** (an anti-forensics tool)
- `My Confession.txt` (232 B, 2007-08-14) states guilt but **doesn't say what of**, so it carries little weight alone
- `How to Steal Cars.txt` (2007-08-15), an article copy that loosely fits the title scan and `Car Titles` folder

## 9. Conclusion

| Allegation | Finding | Strength |
|---|---|---|
| **Who used the computer** | Wes Mantooth: 96 logins; all artifacts are in his profile; the other active account stopped before the activity | 🟢 Strong |
| **Credit card / ATM skimming fraud** | ATM-skimming searches, ATM and camera images, `ATM_THEFTS1.ppt`, `CC Nums.xls`, device photos sent by email | 🟢 Supported |
| **Check fraud** *(additional)* | Check templates, check images, $8,000 cashier's check scan, `Checks` folder, "check washing" search | 🟢 Supported |
| **Drug manufacturing** | Searches, 3 instruction pages opened, supply/drug images, prescription templates. **No lab or finished-product images** | 🟡 Supports *research/attempt*, not manufacture or possession |
| **Anti-forensics** | BestCrypt run (prefetch), TrueCrypt, BitLocker key files, Evidence Washer cookie, forensic tools installed | 🟡 Indicates intent to hide data |

**Overall:** the evidence supports that Wes Mantooth used this computer to **research and plan credit card skimming and check fraud** and to **research methamphetamine manufacturing**. This image alone can't prove the crimes were carried out.

## 10. Limitations & Recommendations

- **Removable media:** key files were opened from E: and F:, which aren't in this image. **Acquire and examine the 15 USB devices** listed in `USBSTOR`, starting with the SanDisk Cruzer Mini (E:) and the UT_USB20 flash drive (F:).
- **Encrypted containers:** BestCrypt/TrueCrypt volumes couldn't be opened. Search for container files and recover the BitLocker key files.
- **Email:** examine full message headers and recipients to identify who received the attachments.
- **Single hash at acquisition:** only MD5 was recorded originally. SHA-256 should be captured at acquisition going forward.

---

## 🧠 Skills Demonstrated

`Evidence integrity & hash verification` · `E01 image handling` · `Windows registry forensics (SAM, SYSTEM, SOFTWARE, NTUSER.DAT)` · `USB device attribution` · `Web history & cache reconstruction` · `File carving` · `Timeline correlation across tools` · `Anti-forensics identification` · `Objective, evidence-based reporting`

Related: [dfir-toolkit](https://github.com/kamronw23/dfir-toolkit) (scripts that automate parts of this workflow) · [dfir-cheatsheets](https://github.com/kamronw23/dfir-cheatsheets) · [Portfolio](https://github.com/kamronw23/Portfolio)
