# REA: เครื่องมือจัดการเครือข่ายที่ศึกษา และสิ่งที่นำมาใช้กับ PandoraBox

ศึกษาจากเอกสารทางการ, โค้ดบน GitHub และคู่มือนักพัฒนา (ไม่ได้ติดตั้งหรือแกะโปรแกรม)
หลักการ: **นำแนวคิดและโครงสร้างมาออกแบบใหม่เอง ไม่คัดลอกโค้ด** เพราะ Zabbix / LibreNMS เป็น GPL

## 1. สรุปแต่ละเครื่องมือ

### Oxidized (backup config, Ruby)
- ท่อการทำงาน: **source** (รายชื่ออุปกรณ์) → **model** (วิธีคุยกับ OS แต่ละแบบ เช่น `ios.rb`) → **input** (SSH/Telnet) → **output** (Git commit ต่อการเปลี่ยนแปลง)
- model ตัด "บรรทัดที่เปลี่ยนเองตลอด" ออกก่อนเก็บ (timestamp ฯลฯ) เพื่อไม่ให้เกิด diff ปลอม
- ดึง config ทันทีเมื่อได้ event ว่ามีการแก้ config (ผ่าน syslog)
- ที่มา: [ytti/oxidized README](https://raw.githubusercontent.com/ytti/oxidized/master/README.md), [Oxidized in Docker](https://oneuptime.com/blog/post/2026-02-08-how-to-run-oxidized-in-docker-for-network-config-backup/markdown)

### Nautobot Golden Config (compliance, Python)
- 4 ส่วน: **backup** (config จริง) · **intended** (config ที่ควรเป็น จาก template + ข้อมูล) · **compliance** (เทียบ 2 อย่างแยกตาม "feature") · **remediation** (สร้างคำสั่งที่ต้องส่งเพื่อให้กลับมา compliant)
- เปิด/ปิดแต่ละส่วนได้ด้วย config flag, remediation ใช้ไลบรารี hier_config, ผลลัพธ์กลายเป็น "config plan" ที่ต้องอนุมัติก่อน deploy
- ที่มา: [Golden Config docs](https://docs.nautobot.com/projects/golden-config/), [ADR](https://docs.nautobot.com/projects/golden-config/en/latest/dev/arch_decision/), [NTC: remediation](https://networktocode.com/?p=5269), [hier_config](https://github.com/netdevops/hier_config)

### Zabbix (monitoring, C + PHP frontend)
- **Trigger** = เงื่อนไขบนค่าที่เก็บ → เปลี่ยนจาก OK เป็น **Problem**, มีระดับ **severity**, กด **acknowledge** ได้ และปิดเองเมื่อเงื่อนไขหาย (recovery)
- หน้า **Problems** กรองตาม host / severity / tag, **Low-Level Discovery** สร้าง item ต่อ interface อัตโนมัติจาก OID index
- **Maps**: แผนที่ที่แสดงสถานะปัญหาบนโหนด, **Dashboard widgets**: Problems by severity, Host availability, Top hosts
- ที่มา: [What is Zabbix](https://www.zabbix.com/documentation/current/manual/introduction), [Dashboard widgets](https://www.zabbix.com/documentation/current/en/manual/web_interface/frontend_sections/dashboards/widgets_overview), [Problems by severity](https://www.zabbix.com/documentation/devel/en/manual/web_interface/frontend_sections/dashboards/widgets/problems_severity)

### LibreNMS (monitoring, PHP/Laravel)
- ค้นหาอุปกรณ์อัตโนมัติจาก CDP/LLDP/ARP/OSPF, เก็บลิงก์เพื่อนบ้านทุกครั้ง แต่ "เพิ่มเป็นอุปกรณ์ใหม่" เป็นตัวเลือกแยก
- โค้ดแยกเป็น **โมดูล discovery / poller** ต่อหัวข้อ และ **ต่อ OS** (`LibreNMS/OS/<os>.php`), ข้อมูล OS ง่ายๆ อยู่ใน **YAML definitions** ไม่ใช่โค้ด
- ที่มา: [Code Structure](https://docs.librenms.org/Developing/Code-Structure), [Auto Discovery](https://docs.librenms.org/Extensions/Auto-Discovery), [Initial Detection](https://docs.librenms.org/Developing/os/Initial-Detection/)

### NetBox (source of truth, Python/Django)
- แยกเป็น **app ต่อโดเมน** (dcim, ipam, …) ทุก app มีชุดไฟล์เดียวกัน: `models` · `filtersets` · `tables` · `forms` · `views` · `urls` · `api/serializers` + เมนูนำทางแยกไฟล์
- **devicetype-library** (ลิขสิทธิ์ **CC0** ใช้ได้อิสระ): YAML ต่อรุ่นอุปกรณ์ ระบุ interface ทุกพอร์ต
- ที่มา: [Adding models](https://netboxlabs.com/docs/netbox/development/adding-models), [Plugins](https://netboxlabs.com/docs/netbox/plugins/development), [devicetype-library](https://awesome.ecosyste.ms/projects/github.com%2Fnetbox-community%2Fdevicetype-library)

### Cisco Catalyst Center (PnP onboarding, เชิงพาณิชย์)
- อุปกรณ์ใหม่ขึ้นเป็น **Unclaimed** → ผู้ใช้ **Claim** พร้อมเลือก site + **Day-0 template** → provisioning; Day-0 เป็นการส่งครั้งเดียวมี rollback, Day-N ส่งทีละบรรทัด
- ที่มา: [Device Onboarding Guide](https://developer.cisco.com/docs/catalyst-center/device-onboarding/), [Switch onboarding](https://www.cisco.com/c/en/us/support/docs/cloud-systems-management/catalyst-center/225887-understand-switch-onboarding-through.html)

## 2. สิ่งที่นำมาใช้กับ PandoraBox

| ได้แนวคิดจาก | ใน PandoraBox | ไฟล์ |
|---|---|---|
| Oxidized model + strip volatile lines | **Config backup** อัตโนมัติ, เก็บเฉพาะเมื่อเปลี่ยน (hash), ดู diff ระหว่างเวอร์ชัน, ดึงทันทีเมื่อได้ trap `configChange` | `pandora/backup.py` |
| Oxidized model ต่อ OS / LibreNMS OS definitions | **Platform definitions**: คำสั่ง backup, บรรทัดที่ต้องตัด, netmiko type ต่อ IOS / IOS-XE ที่เดียว | `pandora/platforms.py` |
| Golden Config backup/intended/compliance/remediation | **Compliance แยกตาม feature** (hostname, mgmt VLAN, mgmt ports, SSH/VTY, SNMP, role) + **remediation** ที่ต้องกดอนุมัติก่อนส่ง | `pandora/compliance.py` |
| Zabbix trigger / problem / severity / ack / recovery | **Problems**: กฎแจ้งเตือนจาก SNMP poll, trap, compliance และสถานะ provisioning พร้อม severity, ack และปิดเอง | `pandora/alerts.py` |
| Zabbix dashboard widgets | **Dashboard**: problems by severity, availability, ขั้นตอน onboarding, CPU สูงสุด, เหตุการณ์ล่าสุด | `web/js/views/dashboard.js` |
| Zabbix maps / LibreNMS neighbours | **Topology** แสดงสีตามปัญหา, ลิงก์แดงเมื่อพอร์ตล่ม, คลิกโหนดเพื่อไปหน้าอุปกรณ์, จำตำแหน่งโหนด | `web/js/views/topology.js` |
| LibreNMS device overview | **หน้า Device** รวม: ข้อมูล, interfaces, config (backup/diff/compliance), terminal, ประวัติ | `web/js/views/device.js` |
| Catalyst Center Unclaimed → Claim → Day-0 | **Onboarding แบบ stepper**: เลือก → role/template → ตรวจ conflict → claim | `web/js/views/inventory.js` |
| NetBox app ต่อโดเมน + filtersets | **Backend แยก router ต่อโดเมน** (`pandora/api/*.py`), inventory มี search/filter/CSV export | `pandora/api/` |
| NetBox devicetype-library (CC0) | อ่านไฟล์ YAML ของ library ได้เพื่อรู้ชื่อพอร์ตของรุ่นที่ตารางในตัวไม่รู้จัก | `pandora/devicetypes.py` |

## 3. สิ่งที่ตั้งใจไม่ทำ
- ระบบ monitoring เต็มรูปแบบ (กราฟระยะยาว, proxy, หลายพันอุปกรณ์): ให้ส่งต่อไป Zabbix / LibreNMS แทน
- Git เป็นที่เก็บ backup: ใช้ SQLite ที่มีอยู่ (เวอร์ชัน + hash) ก่อน, ย้ายไป Git ได้ภายหลังถ้าต้องการ
- hier_config: ยังยืนยัน license ไม่ได้ จึงเขียนตัวเทียบแบบ block (parent/children) เองแบบเล็ก ครอบคลุมเคสของ template เรา

## 4. รอบ 2: อ่านซอร์สโค้ดจริงแล้วนำมาใช้ (ให้เครดิตใน NOTICE)

| โปรเจกต์ (ไลเซนส์) | ไฟล์ที่อ่าน | นำมาใช้ที่ |
|---|---|---|
| Oxidized (Apache-2.0) | `lib/oxidized/model/ios.rb` | กฎซ่อน secret ~25 แบบใน `pandora/db.py` (แก้ให้ไม่ทำลายบรรทัด SNMPv3) และบรรทัด error ที่ตัดทิ้งใน `pandora/platforms.py` |
| hier_config (MIT) | `hier_config/platforms/cisco_ios/driver.py` | บรรทัดที่ไม่นำมาเทียบ, คำสั่งที่แทนค่าเดิมได้โดยไม่ต้อง `no`, ลำดับคำสั่ง (switchport mode ก่อน, no shutdown ท้ายสุด) ใน `pandora/compliance.py` |
| WebSSH (MIT) | `webssh/handler.py`, `worker.py`, `static/js/main.js` | โปรโตคอล terminal: `{"data"}` / `{"resize"}` จากเบราว์เซอร์, bytes แบบ binary กลับ ใน `pandora/api/terminal.py` (ปรับ: อ่านแบบ blocking + timeout สั้น, ส่ง Break ได้, UTF-8 decode โดย xterm) |
| NetBox (Apache-2.0) | `netbox/utilities/paginator.py`, `templates/inc/paginator.html` | ตัวเลือกจำนวนต่อหน้า + จำกัดค่าสูงสุดใน `pandora/api/inventory.py`, รายการเลขหน้าแบบ smart ใน `pandora/web/js/grid.js` |
