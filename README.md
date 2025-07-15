#  Smart URL Safety Checker

> **"Detect phishing links before they detect you."**  
> A machine learning–powered Flask web app that intelligently predicts whether a given URL is **safe or phishing**—in real-time.

---

##  Abstract

Phishing remains one of the most common and dangerous cybersecurity threats, deceiving users into sharing sensitive information via fake links. This project presents a web-based application powered by machine learning to automatically detect phishing URLs by analyzing over 30 URL-based features.

Using models like XGBoost and Random Forest, the system can distinguish between legitimate and malicious URLs with high accuracy, all accessible through a simple, clean web interface built using Flask.

---

##  Introduction

In an increasingly digital world, phishing attacks have grown more sophisticated and widespread. Users often lack the tools or awareness to identify whether a URL is trustworthy. This project is a step toward closing that gap—using artificial intelligence to **automate phishing detection**.

The goal is to empower users with a fast, accurate, and reliable tool that evaluates any URL they enter and provides an instant risk assessment.

---

##  Project Overview

The Smart URL Safety Checker is a full-stack machine learning project with:

-  A Flask-based **web application** interface
-  A feature extractor that analyzes **URL structure and patterns**
-  A machine learning model (XGBoost) trained on a labeled dataset of phishing and legitimate URLs
-  Model evaluation using accuracy, precision, and confusion matrix
-  Deployment-ready architecture for local or cloud hosting

---

##  Tech Stack

| Layer       | Tools/Technologies Used                          |
|------------|--------------------------------------------------|
| **Languages**    | Python, HTML, CSS                               |
| **Framework**    | Flask (for web application)                    |
| **ML Libraries** | Scikit-learn, XGBoost, Pandas, NumPy           |
| **Visualization**| Matplotlib, Seaborn                            |
| **Environment**  | Google Colab , VS Code                      |
| **Version Control** | Git, GitHub                               |

---

## Key Features

- Intelligent ML-based classification of URLs
- Extracts over 30 URL-based features (length, symbols, domain type, etc.)
- XGBoost classifier with ~97% accuracy
- Easy-to-use web interface for real-time predictions
- Future-ready: can be expanded into a browser plugin or API

---

## Results Summary

| Model            | Accuracy |
|------------------|----------|
| XGBoost        | 0.970 |
| Decision Tree    | 0.958   |
| Logistic Regression | 0.934 |
| KNN              | 0.959   |
| Naive Bayes      | 0.605    |

---

##  Folder Structure

```bash
Smart-URL-safety-checker/
├── app.py                   # Flask Web Application (backend)
├── ml(1).ipynb              # Machine Learning training notebook (Google Colab)
├── phishing_model.pkl       # Trained ML model (XGBoost saved using Pickle)
├── phishing_site_data.csv   # Dataset used for training and testing
├── README.md                # Project documentation (you're reading it)
│
├── templates/
│   └── index.html           # Frontend UI – HTML page for user URL input
│
├── static/
│   └── style.css            # CSS stylesheet for styling the frontend

