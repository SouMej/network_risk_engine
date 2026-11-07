Analyse du trafic réseau mobile et enjeux de la vie privée
Présentation du projet
    Ce projet a pour objectif d’apprendre à capturer et analyser les échanges réseau d’un téléphone Android, à identifier les adresses IP et les requêtes DNS contactées, à les associer aux applications utilisées, et à comprendre les enjeux liés à la vie privée et à l’exploitation des données personnelles.
    Les captures réseau ont été réalisées lors d’une utilisation normale d’applications populaires telles que Facebook, WhatsApp et Amazon, puis analysées manuellement avec Wireshark et automatiquement à l’aide d’un script Python.

Objectifs

    Capturer le trafic réseau généré par des applications Android
    Identifier les adresses IP contactées et leur origine géographique
    Analyser les requêtes DNS associées aux services utilisés
    Mettre en évidence les données personnelles potentiellement exposées
    Comprendre comment détecter des comportements anormaux dans un trafic réseau

Outils utilisés

    PCAPdroid : capture du trafic réseau sur l’émulateur Android
    Wireshark : analyse manuelle des trames réseau
    Python (Scapy) : analyse automatisée des fichiers PCAP
    Android Emulator / Android Studio

Capture du trafic réseau

    Le trafic réseau a été capturé lors des actions suivantes :
    Connexion à Facebook et WhatsApp
    Scroll du fil d’actualité
    Envoi de messages
    Accès à des sites e-commerce (Amazon)

Les fichiers PCAP générés par PCAPdroid sont disponibles dans le dossier pcap/ du dépôt.


Analyse automatisée avec Python
🔹 Analyse des adresses IP

Le script Python extrait :
    Les adresses IP publiques et privées
    Leur origine géographique (ASN, pays, organisation)
    Le type d’infrastructure (Google, Facebook, Amazon, CDN, etc.)

🔹 Analyse DNS

L’analyse DNS permet d’identifier :
Les domaines contactés
Les services précis utilisés par chaque application

Analyse des attaques simulées
🔸1. Exfiltration de données (HTTP Exfiltration)

Une attaque simulée d’exfiltration a été analysée à partir d’un PCAP.
Caractéristiques détectées :
    Volume anormal de données envoyées
    Multiples requêtes HTTP POST
    Communication répétée avec une IP externe

🔸2. Attaque par force brute (Brute Force)

Une attaque de type brute force a également été simulée.
Indices observés :
    Grand nombre de tentatives sur un même port
    Fréquence élevée des requêtes
    Comportement répétitif

🔸 3. Attaque par déni de service (DoS)

L’attaque DoS consiste à saturer une machine cible en lui envoyant
un nombre excessif de paquets réseau
Indices observés :
    Très grand nombre de paquets envoyés vers une même IP cible
    Rafales de trafic sur une courte période
    Déséquilibre important entre le trafic entrant et sortant
    Répétition des mêmes types de paquets