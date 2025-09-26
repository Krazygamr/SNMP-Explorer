# SNMP Explorer

A lightweight Windows-based tool for exploring, configuring, and managing SNMP monitoring for **FortiGate** and other SNMP-enabled devices.  
Built with **Python + Tkinter**, designed to run locally without admin rights, and integrates directly with **Prometheus + snmp_exporter + Grafana**.  

👉 GitHub Repository: [Krazygamr/SNMP-Explorer](https://github.com/Krazygamr/SNMP-Explorer)

---

## ✨ Features Overview
- 🔑 **Connection Tab** — Manage SSH connections and save/load profiles.  
- 📂 **Catalog Tab** — Browse MIB catalogs, add/remove OIDs, manage categories.  
- 📊 **Dashboard Tab** — Automatically generate Grafana dashboards.  
- 🛠️ **Installation Tab** — Verify prerequisites and environment status.  
- 📡 **Prometheus Tab** — View logs, validate configs, and check exporter status.  
- 🔧 **SNMP Exporter Integration** — Fetch, edit, push, and validate `snmp.yml` on your Pi.  

---

## 🖥️ How to Use Each Tab

### 🔑 Connection Tab
**Purpose:** Manage how the tool connects to your SNMP Exporter host (e.g., Raspberry Pi).  

**Workflow:**
1. Enter:
   - **Hostname/IP** of your Pi or SNMP exporter host.  
   - **Username** (e.g., `pi`).  
   - **Password** *or* provide an SSH key path.  
   - (Optional) **Grafana API key** (used by Dashboard Tab).  
2. Click **Save Profile** to store this configuration for later reuse.  
3. Click **Load Profile** to restore saved settings.  
   - If a password was saved, it will auto-populate.  

✅ Best Practice: Create one profile per device (e.g., “FortiGate Lab” or “Prod Pi Monitor”).  

---

### 📂 Catalog Tab
**Purpose:** Decide what metrics to monitor by selecting OIDs from MIB catalogs.  

**Details:**
- Catalog files are simple **JSON/YAML** maps that include:  
  - `OID` → numeric SNMP path (e.g., `.1.3.6.1.4.1.12356.101.4.1.3.0`).  
  - **Name** → short alias (e.g., `fgSysCpuUsage`).  
  - **Category** → functional grouping (CPU, Memory, Sessions, Interfaces, etc.).  
  - **Description** → human-readable explanation.  
- The app comes with a **FortiGate catalog** but you can add your own.  
- Categories make it easy to toggle whole groups of OIDs at once.  

**Workflow:**
1. Load a catalog file from the `catalog/` folder.  
2. Browse OIDs by category.  
3. Add OIDs to your active monitoring set (check the box).  
4. Remove OIDs if not needed.  
   - Safety check: can’t delete a walk entry if metrics depend on it.  
5. Save the updated set → written into `snmp.yml`.  

✅ Example: Select CPU, memory, session count, and interface bandwidth from the FortiGate catalog.  

---

### 📊 Dashboard Tab
**Purpose:** Generate Grafana dashboards automatically from selected metrics.  

**Details:**
- Uses your **Grafana API key** (stored in your profile).  
- Reads the active `snmp.yml` to find monitored OIDs.  
- Creates panels in Grafana for each OID with proper naming and labeling.  
- Dashboards are built dynamically — every time you add/remove metrics, you can regenerate a new dashboard.  
- Sessions can be saved locally, so you don’t need to rebuild layouts every time.  

**Workflow:**
1. Ensure you have a valid **Grafana API key** entered in the Connection Tab.  
2. Click **Build Dashboard**:  
   - A new Grafana dashboard is created with one panel per OID.  
   - Panels are labeled using the OID name/description.  
3. Use **Save Session** to store the layout (e.g., “FortiGate Basic Dashboard”).  
4. Use **Load Session** to restore a saved layout.  
5. If the exporter config breaks, click **Repair snmp_exporter unit** to fix it.  

✅ Example: Build a dashboard with CPU, memory, and sessions in the first row, then interface traffic charts in the second row.  

---

### 🛠️ Installation Tab
**Purpose:** Check system requirements and confirm that Prometheus, Grafana, and SNMP exporter are set up correctly.  

**Details:**
- Runs a **verification check** when clicked.  
- Confirms:  
  - `snmp_exporter` service is installed and enabled.  
  - `/etc/snmp_exporter/snmp.yml` exists in the expected location.  
  - Prometheus config loads without error.  
  - Grafana is reachable (if API key provided).  
- Outputs results with `[INFO]`, `[WARN]`, `[ERROR]` tags.  

**Workflow:**
1. Click **Run Verification**.  
2. Read the results in the output window:  
   - `[INFO]` → Everything is fine.  
   - `[WARN]` → Not critical, but might affect monitoring.  
   - `[ERROR]` → Must be fixed before continuing.  
3. Adjust your setup as needed (edit configs, restart services).  

✅ Example: If you see `[WARN] unit points to '(none)'`, you know to update your exporter config path.  

---

### 📡 Prometheus Tab
**Purpose:** Validate your Prometheus and exporter setup without leaving the app.  

**Workflow:**
1. Click **Check Logs**:
   - Displays latest Prometheus logs (errors, warnings, config reloads).  
2. Look for `[ERROR]` entries — indicates config problems.  
3. Use **toast notifications** to confirm success/failure.  

✅ Example: After pushing a new config, run this to confirm Prometheus reloaded successfully.  

---

### 🔧 SNMP Exporter Integration
**Purpose:** Directly manage your `snmp.yml` on the Pi.  

**Workflow:**
1. Connect via **Connection Tab**.  
2. Click **Pull Config** to download `/etc/snmp_exporter/snmp.yml`.  
3. Make changes via the **Catalog Tab**.  
4. Click **Push Config** to upload a new version and restart the service.  
5. Use **Verify Config** to test scrape output.  

✅ Example: Add a new OID, push the config, and immediately verify the scrape shows new metrics.  

---

## 📦 Project Structure
```
SNMP-Explorer/
│
├── app.py               # Main app entry point
├── requirements.txt     # Python dependencies
│
├── common/              # Shared context + utilities
│   └── context.py
│
├── catalog/             # OID catalog definitions (JSON/YAML)
│   └── fortigate.json
│
├── dashboard/           # Grafana dashboard builder
│   └── builder.py
│
├── installation/        # Verification checks for environment
│   └── verifier.py
│
└── docs/                # Documentation, notes, examples
```

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/Krazygamr/SNMP-Explorer.git
cd SNMP-Explorer
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the app
```bash
python app.py
```

---

## 📌 Roadmap
- [ ] Catalog Tab: add search, filters, favorites.  
- [ ] Dashboard Tab: multiple layout templates, alert support.  
- [ ] Installation Tab: include Grafana health checks.  
- [ ] Prometheus Tab: live scrape output viewer.  
- [ ] Packaging: standalone `.exe` build via PyInstaller.  

---

## ⚖️ License
Creative Commons NonCommercial license

---

## 🤝 Contributing
Pull requests and issue reports are welcome.  
Fork the repo at 👉 [Krazygamr/SNMP-Explorer](https://github.com/Krazygamr/SNMP-Explorer)

---
