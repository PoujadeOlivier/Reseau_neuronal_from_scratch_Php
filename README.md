Compréhension du fonctionnement d'un réseau neuronal à travers un exercice de détection de motifs XSS.
Code from Scratch, sans librairie externe, afin d'en comprendre les coulisses.

<b>Dataset & Code d'entraînement</b> <br/>
🗃️ <b>Dataset :</b> dataset_tronque.json <br/>
🐘 <b>Code d'entraînement :</b> entrainement_modele_xss.php <br/>

<b>Modèle & Code d'exploitation </b> <br/>
🧠 <b>Modèle :</b> modele_xss.json <br/>
🐘 <b>Code d'exploitation :</b> detecteur_xss.php <br/>
<br/>
<br/>
<br/>


## 🔄 Pipeline

1. ⚙️ **Configuration**

   * Nombre de features
   * Nombre de neurones cachés
   * Taux d'apprentissage
   * Nombre d'epochs

2. 🧩 **Définition des 16 features** extraites d'une chaîne.

3. 🔤 **Normalisation du texte**

   * URLs
   * HTML entities
   * Unicode

4. 🔎 **Extraction des features**.

5. 🗃️ **Chargement du dataset** au format JSON.

6. 📊 **Calcul des statistiques**

   * Moyenne
   * Écart-type de chaque feature

7. 📐 **Normalisation du dataset**.

8. 🎲 **Initialisation aléatoire** des poids et des biais.

9. 🧠 **Entraînement du réseau**

   * Propagation avant (*forward propagation*)
   * Calcul de la *loss*
   * Rétropropagation (*backpropagation*)
   * Mise à jour des poids
   * *Early stopping*

10. 🏆 **Restauration du meilleur modèle**.

11. 🔮 **Fonction de prédiction**.

12. 🧪 **Tests** sur différentes chaînes.

13. 💾 **Export du modèle** au format JSON.

14. 🚀 **Utilisation du modèle** pour effectuer des prédictions.
