<?php

$debut = microtime(true);


// ===========================================
//  MINI RESEAU NEURONAL XSS
// ===========================================



//Si 3 neurones cachés, idée globale
//
//	$weights_hidden = [
//		[0.5, -0.2, 0.3, 0.8, 0.1, -0.1, 0.4, 0.2], // neurone 1
//		[0.3, 0.6, -0.4, 0.2, 0.5, 0.1, -0.2, 0.3], // neurone 2
//		[0.2, -0.1, 0.5, 0.3, 0.0, 0.1, 0.2, -0.3]  // neurone 3
//	];
//
//	$bias_hidden = [0.1, 0.2, 0.05];
//
//	$weights_output = [1.0, -1.2, 0.5];
//
//Puis dans TOUTES les boucles $j passe à 3:
//	for ($j=0; $j<3; $j++) { ... }
//
//
//Ajouter un 3ᵉ neurone caché peut être utile, mais avec nuance.
//
//1. Ce que change un 3ᵉ neurone
//
//Chaque neurone caché apprend à reconnaître un motif (pattern) différent dans les features XSS.
//En ajoutant un 3ᵉ neurone, le réseau peut détecter une caractéristique supplémentaire dans les données XSS.
//Exemple :
//Neurone 1 → détecte la présence de <script>.
//Neurone 2 → détecte la présence d'attributs d'événements (onload, onclick, etc.).
//Neurone 3 → apprend à reconnaître les URI javascript: ou des appels comme alert().
//
//Avec trois neurones, le réseau peut distinguer davantage de types de signatures XSS et améliorer sa précision, 
//à condition de disposer de suffisamment de données d'entraînement.
//
//
//2. Limites
//
//Sur un dataset très petit ou simple, le 3ᵉ neurone n’apporte pas grand-chose.
//Sur des données variées et complexes (beaucoup de types de XSS), 
//un neurone supplémentaire peut aider à capturer des patterns plus subtils.
//Trop de neurones → risque d’overfitting (le réseau apprend trop bien les exemples, 
//mais devient moins efficace sur de nouvelles attaques).
//
//3. Résumé simple
//
//2 neurones suffisent pour un mini exemple ou débuter.
//3 ou 4 neurones peuvent aider si tu as beaucoup de données et des attaques très différentes.
//Chaque neurone supplémentaire = capacité d’apprentissage supplémentaire, mais pas toujours nécessaire.




// ============================
// Configuration
// ============================

$n_features = 16;
$hidden_units = 5; //ici 5 neuronnes cachées

$learning_rate = 0.01;
$epochs = 500; //nombre de passage




// ============================
// Liste des features
// ============================

$feature_names = [

    "length",

    // HTML
    "lt_count",
    "gt_count",

    // Encodages / obfuscation
    "percent_count",          // %3C
    "html_entity_count",      // &#60; &lt;
    "unicode_escape_count",   // \u003C
    "hex_escape_count",       // \x3C
    "octal_escape_count",     // \145

    // Balises HTML dangereuses
    "has_dangerous_tag",

    // Attributs événementiels
    "has_event_handler",
    "event_handler_count",

    // Schémas URI dangereux
    "has_js_scheme",
    "has_data_uri",

    // Fonctions JavaScript sensibles
    "has_dangerous_function",

    // Commentaires / obfuscation
    "has_comment_marker",

    // Complexité
    "special_char_ratio"
];




// ============================
// Normalisation texte
// ============================

function normalize_input(string $s): string
{
    $old = "";
    $pass = 0;

    // Décodage URL multiple (%3C -> <)
    while ($s !== $old && $pass < 3) {
        $old = $s;
        $s = rawurldecode($s);
        $pass++;
    }

    // Décodage HTML (&lt; -> <)
    $s = html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');

    // Décodage Unicode JavaScript (\u003C -> <)
    $s = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', function ($m) {
        return mb_convert_encoding(pack("H*", $m[1]), "UTF-8", "UTF-16BE");
    }, $s);

    return $s;
}




// ============================
// Extraction features
// ============================

// Transforme un texte en un vecteur de 16 caractéristiques (features)
// exploitables par le réseau de neurones.
// Mathématiques / Machine Learning → vecteur : est simplement une liste ordonnée de valeurs,
// ici→ un tableau de 16 nombres représentant les caractéristiques du texte

function extract_features(string $s): array
{
    $normalized = normalize_input($s);
    $lower = strtolower($normalized);

    return [

        // =====================
        // Taille
        // =====================

        strlen($s),

        // =====================
        // HTML
        // =====================

        substr_count($s, '<'),
        substr_count($s, '>'),

        // =====================
        // Encodages (sur brut)
        // =====================

        substr_count($s, '%'),
        preg_match_all('/&#\d+;|&#x[0-9a-f]+;|&[a-z]+;/i', $s),
        preg_match_all('/\\\\u[0-9a-f]{4}/i', $s),
        preg_match_all('/\\\\x[0-9a-f]{2}/i', $s),
        preg_match_all('/\\\\[0-7]{1,3}/', $s),

        // =====================
        // Balises dangereuses
        // =====================

        preg_match('/<(script|svg|img|iframe|object|embed|math)\b/i', $lower) ? 1 : 0,

        // =====================
        // Attributs onxxx=
        // =====================

        preg_match_all('/\bon[a-z]+\s*=/i', $lower) > 0 ? 1 : 0,
        preg_match_all('/\bon[a-z]+\s*=/i', $lower),

        // =====================
        // Schémas URI dangereux
        // =====================

        preg_match('/javascript\s*:/i', $lower) ? 1 : 0,
        preg_match('/data\s*:/i', $lower) ? 1 : 0,

        // =====================
        // Fonctions JavaScript
        // =====================

        preg_match(
            '/\b(alert|eval|confirm|prompt|settimeout|setinterval|function|constructor|atob|btoa|unescape|fromcharcode)\b/i',
            $lower
        ) ? 1 : 0,

        // =====================
        // Commentaires
        // =====================

        preg_match('/<!--|-->|\/\*|\*\/|\/\//', $s) ? 1 : 0,

        // =====================
        // Ratio caractères spéciaux
        // =====================

        strlen($s) ? preg_match_all('/[^a-z0-9\s]/i', $s) / strlen($s) : 0
    ];
}




// ============================
// Activation
// ============================

//On ne garde que si valeur positive, sinon on met 0
function relu($x)
{
    return $x > 0 ? $x : 0;
}

//Transforme n'importe quel nombre en un score en 0 et 1
function sigmoid($x)
{
    return 1 / (1 + exp(-$x));
}




// ============================
// Chargement dataset
// ============================

//https://www.kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning
//Cross site scripting XSS dataset for Deep learning
// 13685 entrées labélisées XSS ou pas
/*
..
  {
    "": 13663,
    "Sentence": "<li><a href=\"/wiki/Articulated_robot\" title=\"Articulated robot\">Articulated </a>",
    "Label": 0
  },
  ..
  {
    "": 13664,
    "Sentence": "<tt onclick=\"alert(1)\">test</tt>",
    "Label": 1
  },
..  
*/  

$json = file_get_contents("dataset.json");
$data = json_decode($json, true);

$dataset = [];

foreach ($data as $row) {
    $dataset[] = [
        $row["Sentence"],
        (int)$row["Label"]
    ];
}




// ============================
// Extraction features UNE SEULE FOIS
// ============================

$X_raw = [];
$Y = [];

foreach ($dataset as $row) {
	// Pour chaque entrées du jeu du dataset, 
	// je récupère le retour de la moulinette extract_features
    $X_raw[] = extract_features($row[0]);
	// Pour chaque entrée du dataset, 
	// je récupère le résultat attendu officiel, le label (0 = normal, 1 = XSS)
    $Y[] = $row[1];
}

// Nombre de lignes (d'exemples) dans le dataset.
$n = count($X_raw); 




// ============================
// Normalisation moyenne écart-type
// ============================

//Initialisation des deux tableaux contenant la moyenne et l'écart-type de chaque feature.
$mean = array_fill(0, $n_features, 0);
$std  = array_fill(0, $n_features, 0);


for ($i = 0; $i < $n_features; $i++) {

	// Calcul de la moyenne de la feature i.
    $somme = 0;

    for ($j = 0; $j < $n; $j++) {
        $somme += $X_raw[$j][$i];
    }

    $mean[$i] = $somme / $n;

	// Calcul de la variance de la feature i.
	//La variance mesure à quel point les valeurs d'une série sont dispersées autour de leur moyenne.
	//Variance faible → les valeurs sont proches de la moyenne.
	//Variance élevée → les valeurs sont très étalées.
    $variance = 0;

    for ($j = 0; $j < $n; $j++) {
        $variance += pow($X_raw[$j][$i] - $mean[$i], 2);
    }

    $std[$i] = sqrt($variance / $n);

	//Sert à éviter une division par zéro pendant la standardisation
	//Le problème arrive si une feature a toujours la même valeur.
    if ($std[$i] == 0) {
        $std[$i] = 0.000000001;
    }
}
/*
echo "nbre de ligne du dataset : ".count($dataset)."<br/><br/>";
echo "nbre de feature : $n_features<br/><br/>";
echo "moyenne <br/>";
print("<pre>".print_r($mean,true)."</pre>");
echo"<br/>";
echo "ecart type <br/>";
print("<pre>".print_r($std,true)."</pre>");exit;
*/

//Voici ce qu'on déduit à ce stade
/*							Feature	Moyenne	Écart-type	Interprétation
"length"					0		108,02	207,45	Très dispersée (probablement la longueur du texte). Quelques très grands textes tirent la moyenne vers le haut.
"lt_count"					1		3,26	3,76	Dispersion normale.
"gt_count"					2		3,26	3,76	Très similaire à la feature 1. Peut-être deux mesures proches.
"percent_count"				3		0,385	2,51	Beaucoup de dispersion par rapport à la moyenne.
"html_entity_count"			4		0,377	1,89	Même remarque.
"unicode_escape_count"		5		0,00022	0,0148	Événement extrêmement rare.
"hex_escape_count"			6		0,00022	0,0191	Idem.
"octal_escape_count"		7		0,00395	0,3145	Très rarement non nulle.
"has_dangerous_tag"			8		0,0446	0,2065	Probablement une feature binaire ou un ratio faible.
"has_event_handler"			9		0,5238	0,4994	Presque exactement une variable binaire équilibrée.
"event_handler_count"		10		0,5240	0,4999	Pareil.
"has_js_scheme"				11		0,0040	0,0633	Très rare.
"has_data_uri"				12		0,0232	0,1504	Rare.
"has_dangerous_function"	13		0,5317	0,4990	Encore une variable binaire.
"has_comment_marker"		14		0,0384	0,1921	Rare.
"special_char_ratio"		15		0,2422	0,1100	Variable continue bien répartie.
*/




// ============================
// Dataset normalisé
// ============================

//Nous allons transformer chaque valeur brute en score z-score
//-> standardisation par score Z (z-score).
//La formule est : z = (x - µ)/σ
//où
//x = la valeur d'origine,
//μ = la moyenne de la feature,
//σ = son écart-type.
//
//Après cette transformation :
//la moyenne des scores Z vaut 0 ;
//l'écart-type des scores Z vaut 1.


//Après la normalisation, 
//toutes les features auront une moyenne proche de 0
//toutes auront un écart-type proche de 1
// cas feature 0 plutôt -2 à +3
// ex:
// pour valeur 20 :    (20-108)/207 = -0.42
// pour valeur 108 :   0
// pour valeur 315 :   1
// pour valeur 730 :   3

// cas feature 8 (feature binaire rare) 
// ex:
// pour valeur 0 : (0 - 0.0446) / 0.2065 = -0.22
// pour valeur 1 : (1 - 0.0446) / 0.2065 =  4.63
//L'interprétation est intéressante :
//
//0 est très fréquent ⇒ il devient une valeur proche de 0 (ici −0,22).
//1 est très rare (≈ 4,5 % des cas) ⇒ il devient une valeur élevée (+4,63).
//
//C'est normal : la normalisation met en évidence que cette feature vaut 1 dans très peu d'exemples.


$X = [];

for ($j = 0; $j < $n; $j++) {

    $ligne = [];

    for ($i = 0; $i < $n_features; $i++)
	{
        //$ligne[$i] = ($X_raw[$j][$i] - $mean[$i]) / $std[$i];
		
		//Il est prudent de protéger le code contre un écart-type nul (si une feature est constante dans tout le dataset)
		//Evite une division par zéro et garantit que le code reste robuste, même si une feature n'apporte aucune variation.
		if ($std[$i] > 0) {
			$ligne[$i] = ($X_raw[$j][$i] - $mean[$i]) / $std[$i];
		} else {
			$ligne[$i] = 0.0;
		}

    }

    $X[] = $ligne;
}


//Rappel
//L'écart-type n'est pas une valeur précise qui s'ajoute ou se retire à chaque donnée.
//C'est une mesure de dispersion qui indique de combien les valeurs s'éloignent généralement de la moyenne.
//L'écart-type mesure une distance autour de la moyenne. L'écart-type est toujours positif (car une distance ne peut pas être négative).
//
//On peut dire :
//
// zone habituelle ≈ moyenne ± ecart-type
//
//Exemple :
//
//Longueur texte : moyenne = 108
//écart-type = 50
//
//On peut regarder une zone autour de la moyenne :
//
//108 - 50 = 58
//108 + 50 = 158
//
//Donc beaucoup de textes auront une longueur autour de 58 à 158 caractères.
//
//Mais ce n'est pas une limite :
//
//certains peuvent faire 20 caractères ;
//certains peuvent faire 300 caractères.


// Avant normalisation  : les variables n'ont pas la même échelle
// Longueur texte       : moyenne 108 caractères (écart important)
// Booléen              : valeurs entre 0 et 1
// Pourcentage chiffres : proportion de chiffres dans le texte (ex: 0.24 = 24%)
//
// Après normalisation (score Z) :
// Chaque variable est recentrée autour de 0.
// Les petites valeurs sont proches de 0, les grandes valeurs s'éloignent de 0.
// Les variables deviennent comparables entre elles.

//
// Après normalisation (score Z)
// Les valeurs sont centrées autour de 0.
// La plupart des valeurs se situent généralement autour de -1 à +1.
// Les valeurs éloignées de 0 indiquent des cas éloignés de la moyenne.


// Exemple :
// Une valeur positive = au-dessus de la moyenne.
// Une valeur négative = en dessous de la moyenne.
// 0 = exactement dans la moyenne.
//
// Cela aide le réseau de neurones à apprendre plus facilement.


// Avant normalisation (moyenne ± écart-type)
// Longueur texte       : 108 ± 207
// Booléen              : 0.52 ± 0.50
// Pourcentage chiffres sur l'ensemble des caractères : 0.24 ± 0.11
//
// Après standardisation (z-score)
// Longueur texte       : moyenne = 0, écart-type = 1
// Booléen              : moyenne = 0, écart-type = 1
// Pourcentage chiffres sur l'ensemble des caractères: moyenne = 0, écart-type = 1
//
// Toutes les variables sont ainsi sur une échelle comparable,
// ce qui facilite et stabilise l'entraînement du réseau de neurones.




//print("<pre>".print_r($X,true)."</pre>");exit;




// ============================
// Création réseau
// ============================

//On crée le tableau qui contiendra tous les poids reliant les 16 features aux neurones cachés.
$weights_hidden = [];

//Pour chaque neurone caché, on crée un poids pour chaque feature.
//Chaque poids est choisi aléatoirement entre -1 et 1.
// ->Initialisation aléatoire des poids reliant les features aux neurones cachés.
// ->Chaque neurone possède un poids pour chacune des 16 features.
for ($j = 0; $j < $hidden_units; $j++) {
    for ($i = 0; $i < $n_features; $i++) {
        $weights_hidden[$j][$i] = (mt_rand() / mt_getrandmax()) * 2 - 1;
    }
}


//Chaque neurone caché possède un biais.
//Au départ, ils valent tous 0.
//Initialisation des biais des neurones cachés
$bias_hidden = [];

for ($j = 0; $j < $hidden_units; $j++) {
    $bias_hidden[$j] = 0;
}

// Initialisation aléatoire des poids reliant les neurones cachés
// au neurone de sortie.
$weights_output = [];

for ($j = 0; $j < $hidden_units; $j++) {
    $weights_output[$j] = (mt_rand() / mt_getrandmax()) * 2 - 1;
}

//Biais du neurone de sortie
//Le neurone de sortie possède également son propre biais.
$bias_output = 0;


/*
16 features
      │
      │ 5 × 16 poids
      ▼
+----------------------+
| 5 neurones cachés    |
+----------------------+
      │
      │ 5 poids
      ▼
+----------------------+
| 1 neurone de sortie  |
+----------------------+

En résumé, cette partie ne fait encore aucun calcul. 
Elle construit simplement le réseau en créant tous les paramètres (poids et biais) 
qui seront ensuite ajustés pendant l'entraînement grâce à la rétropropagation.
*/




// ============================
// Entraînement avec Early stopping
// ============================

//PHP_FLOAT_MAX est une constante PHP qui contient la plus grande valeur positive représentable par un nombre à virgule flottante (float) sur la machine où PHP s'exécute
//on initialise avec une valeur tellement grande qu'elle sera remplacée dès la première vraie valeur de loss
$best_loss = PHP_FLOAT_MAX;

$best_weights_hidden = [];
$best_bias_hidden = [];

$best_weights_output = [];
$best_bias_output = [];

$patience = 50;
$min_delta = 0.0005;
$no_change = 0;

//terme machine learning
// 1 epoch = 1 passage complet sur l'ensemble du dataset
// patience = nombre de epoch sans amélioration tolérées avant d'arrêté l'entrainement
// no_change = compteur des epoch sans amélioration
// ces 3 variables servent au Early Stopping

for ($epoch = 1; $epoch <= $epochs; $epoch++) {

    $loss = 0;

    // Mélange des données à chaque epoch
    $ordre = range(0, $n - 1);
    shuffle($ordre);

    foreach ($ordre as $index) {

        $x = $X[$index];
        $label = $Y[$index];

        // =====================
        // Forward
        // =====================

		//C'est ici que le réseau fait une prédiction

        $h = [];

		//pour chaque neuronne caché (5)
        for ($j = 0; $j < $hidden_units; $j++) {

			//Chaque neuronne commence par son biais
            $somme = $bias_hidden[$j];

			//pour chaque features (16)
            for ($i = 0; $i < $n_features; $i++) {
				//chaque feature est multiplié par son poids
                $somme += $x[$i] * $weights_hidden[$j][$i];
            }

			//une sortie par neuronne caché
			////On ne garde que si valeur positive, sinon on met 0
            $h[$j] = relu($somme);
        }

		//On calcule ensuite le neuronne final sur le même principe

        $sortie = $bias_output;

        for ($j = 0; $j < $hidden_units; $j++) {
            $sortie += $h[$j] * $weights_output[$j];
        }
		
		//Transforme n'importe quel nombre en un score en 0 et 1
		//sigmoid transforme le résultat en probabilité
        $prediction = sigmoid($sortie);

        // =====================
        // Loss
        // =====================

		//Maintenant on calcule la réponse du réseau avec la vérité
		// réponse attentue = 1 
		// réseau = 0.98
		// Très bien, la Loss sera faible
		
		// réponse attentue = 1 
		// réseau = 0.03
		// Très mauvais, la Loss sera grande

		// Cette formule mesure donc à quel point le réseau s'est trompé
		// à chaque exemple  $loss += ...
		// on ajoute son erreur
		// à la fin de l'epoch, on calculera l'erreur moyenne $loss /= $n;
		

		//eps signifie epsilon (ε), un très petit nombre utilisé comme marge de sécurité numérique.
		//En mathématiques et en machine learning, on utilise souvent epsilon pour éviter des problèmes liés aux valeurs extrêmes.
		//Son rôle est de forcer la prédiction à rester strictement entre 0 et 1, sans jamais atteindre exactement 0 ou 1.
		//numerical stability → stabilité numérique, avoid division by zero → éviter une division par zéro, prevent log(0) → éviter un logarithme de zéro
		
		//Pendant l'entraînement on a besoin du epsilon tu fais :
		//log($prediction)
		//log(1 - $prediction)
		//afin d'éviter log(0)

        $eps = 1e-9;
        $prediction = max(min($prediction, 1 - $eps), $eps);

        $loss += -(
            $label * log($prediction)
            + (1 - $label) * log(1 - $prediction)
        );

        // =====================
        // Backpropagation
        // =====================
		
		//C'est la partie qui fait réellement apprendre le réseau
		
		//C'est l'erreur du neuronne de sortie
		//Cette erreur delta indique dans quel sens il faut corriger les poids
		// attendu = 1
		// prédit = 0.7
		// delta = -0.3
		//ou
		// attendu = 0
		// prédit = 0.9
		// delta = -0.9
		
		// Si un poids a participé à une mauvaise prédiction on le corrige un peut
		// Le learning_rate empêche de modifier les poids trop brutalement

		
        $delta_out = $prediction - $label;

        // Sauvegarde avant modification
        $old_output = $weights_output;

        // Couche sortie
        for ($j = 0; $j < $hidden_units; $j++) {
            $weights_output[$j] -= $learning_rate * $delta_out * $h[$j];
        }

        $bias_output -= $learning_rate * $delta_out;


		

        // Couche cachée
        for ($j = 0; $j < $hidden_units; $j++) {

			//L'erreur est "renvoyée" vers chaque neuronne caché
            $delta_hidden = $delta_out * $old_output[$j] * ($h[$j] > 0 ? 1 : 0);

			//Puis chaque poids est ajusté
            for ($i = 0; $i < $n_features; $i++) {
                $weights_hidden[$j][$i] -= $learning_rate * $delta_hidden * $x[$i];
            }

            $bias_hidden[$j] -= $learning_rate * $delta_hidden;
			
			//Le réseau apprend donc progressivement quelles features sont réellement utiles.
        }
    }

    // Moyenne loss
    $loss /= $n;

    echo "Epoch "
        . $epoch
        . " / "
        . $epochs
        . " - loss : "
        . round($loss, 6)
        . "<br>";

    // ============================
    // Vérification amélioration
    // ============================

	//A la fin de chaque epoch on vérifie si le réseau est devenu meilleur
	// Si oui, on sauvegarde tous les poids et on remet le compteur à zéro
	// Si non, on incrémente le compteur et si $patience attend le seuil fixé, ici 50, on arrête l'entraînement
	// Continuer dans ce dernier cas ne servirait plus à rien : le réseau n'apprend plus

    if (($best_loss - $loss) > $min_delta) {

        $best_loss = $loss;
        $no_change = 0;

        // Sauvegarde du meilleur modèle
        $best_weights_hidden = $weights_hidden;
        $best_bias_hidden = $bias_hidden;

        $best_weights_output = $weights_output;
        $best_bias_output = $bias_output;

    } else {

        $no_change++;
    }



    // ============================
    // Early stopping
    // ============================


    if($no_change >= $patience){

        echo
        "Arrêt anticipé epoch "
        .$epoch
        ." - meilleur loss : "
        .round($best_loss,6)
        ."<br>";

       break;
    }



}




// ============================
// Restauration meilleur modèle
// ============================

// On arrive à la dernière étape de l'entraînement
// Pendant toute la phase d'apprentissage, le réseau à continué à modifier ses poids.
// Or, le dernier état n'st pas forcément le meilleur
// Comme à chaque amélioration on sauvegardait les poids,
// on abandonne les derniers poids calculés et on remet ceux qui ont donné la plus faible erreur (Loss)

$weights_hidden = $best_weights_hidden;
$bias_hidden = $best_bias_hidden;

$weights_output = $best_weights_output;
$bias_output = $best_bias_output;

echo "Modèle restauré - meilleur loss : " . round($best_loss, 6) . "<br>";




// ============================
// Prediction
// ============================

// Jusqu'à présent, le réseau aprpenait. Maintenant, il est entraîné.
// Il ne modifie plus ses poids, il s'en sert simplement pour faire des prédictions.

function predict(
    $text,
    $weights_hidden,
    $bias_hidden,
    $weights_output,
    $bias_output,
    $mean,
    $std,
    $hidden_units,
    $n_features
) {
	// Pour LA chaine à vérifier
	// je récupère le retour de la moulinette extract_features.
	// Il faut appliquer exactement les m^me transformation au nouveau texte.
    $x = extract_features($text);

	//Normalisation
    for ($i = 0; $i < $n_features; $i++) {
        $x[$i] = ($x[$i] - $mean[$i]) / $std[$i];
    }

	//Cette partie est la même que le FOWARD de l'entrainement

    $h = [];

    for ($j = 0; $j < $hidden_units; $j++) {

        $s = $bias_hidden[$j];

        for ($i = 0; $i < $n_features; $i++) {
            $s += $x[$i] * $weights_hidden[$j][$i];
        }
		
		//Somme pondéré
        $h[$j] = relu($s);
    }

    $s = $bias_output;

    for ($j = 0; $j < $hidden_units; $j++) {
        $s += $h[$j] * $weights_output[$j];
    }

	// Retourne une valeur comprise en 0 et 1, exemple
	// 0.02 : très probablement normal
	// 0.97 : très probablement XSS
	// au retour de cette fonction
	// on va le comparer à un seuil de décision fixé, par exemple 0.5, on le nomme threshold
	// score > 0.5 -> XSS
	// score < 0.5 -> texte normal
	// le choix de 0. est classique, mais il pourrait être ajusté si on voulait etre plus strict (ex:0.7) ou plus sensible (ex:0.3)
	// mais attention à l'augementation des faux positifs ou des faux négatifs
    return sigmoid($s);
}




// ============================
// Tests
// ============================

$tests = [
    "<img src=x onerror=alert(1)>",
    "hello world",
    "<script>alert(document.cookie)</script>",
    "bonjour comment allez vous"
];

foreach ($tests as $t) {

    $score = predict(
        $t,
        $weights_hidden,
        $bias_hidden,
        $weights_output,
        $bias_output,
        $mean,
        $std,
        $hidden_units,
        $n_features
    );

    echo "<hr>";
    echo htmlspecialchars($t);
    echo "<br>";
    echo "Score : " . round($score, 4);
    echo "<br>";
    echo $score >= 0.5 ? "XSS" : "OK";
}




// ============================
// Export modèle
// ============================


$model = [
    "features" => $feature_names,
    "hidden_units" => $hidden_units,
    "weights_hidden" => $weights_hidden,
    "bias_hidden" => $bias_hidden,
    "weights_output" => $weights_output,
    "bias_output" => $bias_output,
    "mean" => $mean,
    "std" => $std,
    "threshold" => 0.5,
    "trained_on" => date("Y-m-d")
];

echo "<hr>";
// Affiche l'architecture complète du modèle entraîné
// afin de pouvoir la sauvegarder et la réutiliser pour les prédictions.
// -> Exporter le modèle entraîné au format JSON pour réutilisation (poids, biais et paramètres).
// -> je l'utiliserai tel quel dans le fichier : modele_xss.json
echo "<h3>MODELE</h3>";
echo "<textarea style='width:100%;height:400px'>";
echo htmlspecialchars(json_encode($model, JSON_PRETTY_PRINT));
echo "</textarea>";

$duree = microtime(true) - $debut;

echo "<br><br>";
echo "Durée : " . round($duree, 3) . " secondes";

?>