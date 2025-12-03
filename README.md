# MediQR – Health in a Scan

MediQR is a smart, QR-based digital health profile system designed to give **instant access to a patient’s medical details anytime, anywhere**. It solves one of the biggest challenges in healthcare: **lack of immediate medical information during emergencies.**

---

## 🚑 Problem Statement

In emergency situations, patients are often:
- Unconscious  
- Unable to communicate  
- Illiterate  
- Missing their medical files or prescriptions  

This leads to **delays, wrong medications, and life-threatening decisions**.  
Blood bank information is also scattered, making it hard to quickly arrange blood during critical needs.

---

## 💡 Solution — MediQR

MediQR assigns each patient a **unique QR code** linked to a secure cloud record that contains:

- Personal details (age, gender)
- **Blood Group (highlighted)**
- Current health issues
- Ongoing medications with dosage
- Medical history summary
- Emergency contacts

The QR code can be printed on:
- Wristbands  
- ID cards  
- Stickers  
- Wallet cards  

Doctors, ambulances, pharmacies can scan it **to instantly view verified patient information.**

---

## 🤖 AI-Powered Features

### 1️⃣ **AI Drug Interaction Checker**  
Analyzes new prescriptions and warns doctors of:
- Dangerous medicine combinations  
- Overdose risks  
- Allergy triggers  

### 2️⃣ **AI Blood Bank Finder**  
Shows **nearest hospitals/blood banks** with the patient’s blood group availability.  
Saves time → saves lives.

---

## 🎯 Key Features

- Role-based access (Patient/Doctor/Pharmacy/Admin)
- Encrypted cloud database
- Instant QR-based medical profile access
- Live blood availability
- Auto-update of medications after every visit
- Works even for unconscious patients
- High social and medical impact

---

## 🧱 Project Architecture

Patient App → Cloud DB → QR Generator → QR Wristband/ID
↓
Doctor / Ambulance / Pharmacy App
↓
AI Services (Drug Check + Blood Finder)

---

## 🛠️ Tools & Technologies

- **MERN Stack** (MongoDB, Express.js, React.js, Node.js)
- **Firebase** (for QR-linked mobile app)
- **REST APIs**
- **Google Maps API** (for nearest blood banks)
- **ML/AI Models** (for drug interaction)
- **QR Code Generator Libraries**

---

## 📂 Repository Structure

MediQR/
│── README.md
│── /docs
│ ├── Problem_Statement.pdf
│ ├── Abstract.pdf
│ ├── Flowchart.png
│ └── Architecture_Diagram.png
│── /prototype
│ └── UI_Screenshots/
│── /backend
│── /frontend
│── /ai-services

---

## 🌍 Impact

- **Social:** Helps unconscious/elderly patients receive instant care  
- **Medical:** Avoids medication errors via AI  
- **Economic:** Reduces paperwork & hospital workload  
- **Environmental:** Paperless, digital-first system  

---

## 🚀 Future Scope

- Integrating insurance documents
- Linking wearable devices for live vitals
- Multi-language support
- Offline QR emergency mode

---

## 🏆 Summary

MediQR brings healthcare closer, faster, and safer by ensuring that a patient's medical information is **just a scan away** — saving time, preventing medical errors, and protecting lives.
