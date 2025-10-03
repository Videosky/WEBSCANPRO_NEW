## 🔍 Project Overview

**WebScanPro** is an automated security testing tool for web applications, to be developed primarily **in Python 3.x** and augmented with **Machine Learning (ML) / Deep Learning (DL)** techniques where appropriate. The tool will identify common vulnerabilities such as **SQL Injection**, **Cross-Site Scripting (XSS)**, **Broken Authentication**, **Insecure Direct Object References (IDOR)**, and more. ML/DL components will be used for tasks like anomaly detection, automated classification of server responses, and reducing false positives.

> **Mandatory tech stack:** Python (required) + ML/DL (scikit-learn, TensorFlow/PyTorch, or similar).

---

##  Project Outcomes (explicit ML/DL requirement)

- Build a Python-based automated web scanner that implements the listed modules.
- Integrate ML/DL models to assist detection and prioritization of vulnerabilities (for example, classifiers to detect SQLi/XSS-like responses, anomaly detection for unusual server replies, or NLP-based parsing of error messages).
- Provide model training scripts, dataset creation procedures, and evaluation metrics (precision, recall, F1-score).
- Deliver comprehensive reports combining rule-based detections and ML-driven insights.

---

##  Technologies Used

- **Programming language:** Python 3.x (required)
- **Web interaction & scraping:** Requests, BeautifulSoup, Selenium
- **Reporting & templating:** Jinja2, PDFKit / WeasyPrint
- **ML/DL (required integration):** scikit-learn (baseline models), TensorFlow or PyTorch (for deep models)
- **Data tooling:** pandas, numpy, joblib (model persistence)
- **Deployment/target platforms:** Docker
- **Target apps for testing:** DVWA
