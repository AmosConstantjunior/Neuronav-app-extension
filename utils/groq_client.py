import requests
import cv2
import numpy as np


def call_groq(messages, api_key, **model_params):
    """
    Appelle l'API Groq pour obtenir des complétions ou d'autres résultats
    en utilisant un modèle spécifié et une clé d'API fournie.

    :param messages: Liste des messages à envoyer à l'API
    :param api_key: La clé API Groq pour l'authentification
    :param model_params: Paramètres additionnels pour configurer l'API (par exemple, température, longueur, etc.)
    :return: La réponse de l'API Groq sous forme de dictionnaire
    """
    
    # URL de l'API Groq
    url = "https://api.groq.com/v1/complete"
    
    # Construction du payload de la requête
    payload = {
        "model": "groq-model",  # Le modèle que tu utilises avec Groq
        "messages": messages,
        **model_params
    }
    
    # Construction des headers avec la clé API fournie
    headers = {
        "Authorization": f"Bearer {api_key}",  # Utilisation de l'API Key passée en paramètre
        "Content-Type": "application/json"
    }
    
    # Appel à l'API Groq
    response = requests.post(url, json=payload, headers=headers)
    
    if response.status_code == 200:
        return response.json()  # Retourner la réponse JSON si le code est 200
    else:
        return {"error": "Erreur de communication avec l'API Groq", "status_code": response.status_code}


def detect_objects(image):
    # Charger le modèle YOLOv8 (assurez-vous que le fichier .onnx existe)
    net = cv2.dnn.readNet("yolov8.onnx")

    # Obtenir les dimensions de l'image
    height, width = image.shape[:2]

    # Prétraiter l'image pour YOLO
    blob = cv2.dnn.blobFromImage(image, 1/255.0, (640, 640), (0, 0, 0), True, crop=False)
    net.setInput(blob)

    # Exécuter la détection
    outputs = net.forward()

    # Liste pour stocker les objets détectés
    detected_objects = []

    # Post-traitement pour extraire les résultats des objets détectés
    for out in outputs:
        for detection in out:
            scores = detection[5:]
            class_id = np.argmax(scores)
            confidence = scores[class_id]
            
            if confidence > 0.5:  # Seulement les détections avec une confiance > 50%
                center_x = int(detection[0] * width)
                center_y = int(detection[1] * height)
                w = int(detection[2] * width)
                h = int(detection[3] * height)

                # Détection de l'objet
                detected_objects.append({
                    "class_id": class_id,
                    "confidence": confidence,
                    "bbox": [center_x, center_y, w, h]
                })

    return detected_objects
