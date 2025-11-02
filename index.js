import express from "express";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import axios from "axios";


import { v4 as uuidv4 } from "uuid";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware JSON
app.use(express.json());

// Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// ---------------- MIDDLEWARE AUTH ----------------
function verifyAdmin(req, res, next) {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ error: "Token manquant" });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Token invalide" });

    jwt.verify(token, process.env.JWT_SECRET || "SECRET_KEY", (err, user) => {
      if (err) return res.status(403).json({ error: "Token invalide ou expiré" });
      if (user.role !== "admin") return res.status(403).json({ error: "Accès refusé : admin requis" });

      req.user = user;
      next();
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur auth" });
  }
}

function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ error: "Token manquant" });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Token invalide" });

    jwt.verify(token, process.env.JWT_SECRET || "SECRET_KEY", (err, user) => {
      if (err) return res.status(403).json({ error: "Token invalide ou expiré" });
      req.user = user;
      next();
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur auth" });
  }
}
// ===================== UTILISATEUR CONNECTÉ =====================
app.get("/api/me", verifyToken, async (req, res) => {
  try {
    const { data, error } = await supabase.from("users").select("*").eq("id", req.user.id).single();
    if (error) return res.status(404).json({ error: "Utilisateur non trouvé" });
    res.json({ user: data });
  } catch (err) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// ===================== GESTION DES UTILISATEURS =====================
app.get("/api/users", async (req, res) => {
  try {
    console.log("-> /api/users called");

    // Essaye d'abord toutes les colonnes pour vérifier ce que Supabase renvoie
    const { data, error } = await supabase.from("users").select("*");

    if (error) {
      console.error("Supabase select error /api/users:", error);
      // renvoie l'objet d'erreur complet pour debug (côté dev)
      return res.status(400).json({ error });
    }

    // Supprime le champ password avant d'envoyer
    const safeUsers = (data || []).map(u => {
      const { password, ...rest } = u;
      return rest;
    });

    console.log(`/api/users -> found ${safeUsers.length} users`);
    return res.json({ users: safeUsers });
  } catch (err) {
    console.error("Server error /api/users:", err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get("/api/admin/users", verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from("users").select("*");
    if (error) return res.status(400).json({ error });
    return res.json({ users: data });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

/// ===================== REGISTER / LOGIN =====================
app.post("/api/register", async (req, res) => {
  try {
    const { nom, prenom, phone, password, role = "user" } = req.body;
    if (!nom || !prenom || !phone || !password)
      return res.status(400).json({ error: "Champs requis manquants" });

    // Vérifier doublon
    const { data: existing } = await supabase.from("users").select("id").eq("phone", phone).single();
    if (existing) return res.status(400).json({ error: "Ce numéro est déjà utilisé" });

    const hashed = await bcrypt.hash(password, 10);

    // Si admin => active direct, sinon demande en attente
    const is_active = role === "admin";

    const { data, error } = await supabase
      .from("users")
      .insert([
        {
          id: uuidv4(),
          nom,
          prenom,
          phone,
          password: hashed,
          role,
          is_active,
          approved: is_active,
          pending_approval: !is_active,
        },
      ])
      .select();

    if (error) return res.status(500).json({ error });
    return res.status(201).json({ message: "Inscription en attente de validation", user: data[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;

    // Vérifie les champs
    if (!phone || !password)
      return res.status(400).json({ error: "Téléphone et mot de passe requis" });

    // Cherche l'utilisateur
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("phone", phone)
      .single();

    if (error || !user)
      return res.status(404).json({ error: "Utilisateur non trouvé" });

    // ✅ Vérifie si le compte est désactivé
    if (user.is_active === false) {
      return res.status(403).json({
        error: "Votre compte a été désactivé. Veuillez contacter l’administrateur.",
      });
    }

    // ✅ Vérifie si le compte est en attente d’approbation
    if (user.approved === false && user.pending_approval === true) {
      return res.status(403).json({
        error: "Votre compte est en attente d’approbation par un administrateur.",
      });
    }

    // Vérifie le mot de passe
    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(401).json({ error: "Mot de passe incorrect" });

    // Génère le token JWT
    const token = jwt.sign(
      { id: user.id, role: user.role, phone: user.phone },
      process.env.JWT_SECRET || "SECRET_KEY",
      { expiresIn: "7d" }
    );

    // Supprime le mot de passe du retour
    const { password: _, ...safeUser } = user;

    return res.json({
      message: "Connexion réussie",
      token,
      user: safeUser,
    });
  } catch (err) {
    console.error("Erreur login:", err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});


// ---------------- CRUD MATIERES ----------------
app.get("/api/admin/matieres", verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from("matieres").select("*");
    if (error) return res.status(400).json({ error });
    return res.json({ matieres: data });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/admin/matieres", verifyAdmin, async (req, res) => {
  try {
    const { nom } = req.body;
    if (!nom) return res.status(400).json({ error: "Nom de matière requis" });

    const { data, error } = await supabase.from("matieres").insert([{ nom }]).select();
    if (error) return res.status(500).json({ error });

    return res.status(201).json({ message: "Matière ajoutée", matiere: data[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// ---------------- LISTE DES QUESTIONS PAR SUJET ----------------
// ---------------- CRUD QUESTIONS PAR SUJET ----------------
app.get("/api/admin/matieres/:matiere_id/sujets/:sujet_id/questions", verifyAdmin, async (req, res) => {
  try {
    const { matiere_id, sujet_id } = req.params;

    const { data, error } = await supabase
      .from("questions")
      .select("*")
      .eq("matiere_id", matiere_id)
      .eq("sujet_id", sujet_id)
      .order("id", { ascending: true });

    if (error) return res.status(400).json({ error });

    return res.json({ questions: data });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});


app.post("/api/admin/matieres/:id/questions", async (req, res) => {
  try {
    const matiere_id = parseInt(req.params.id);
    const { question, reponse, options, sujet_id } = req.body;

    // Vérification des champs obligatoires
    if (!question || !reponse || !sujet_id) {
      return res.status(400).json({
        error: "Les champs 'question', 'reponse' et 'sujet_id' sont obligatoires.",
      });
    }

    // Vérifier si la matière existe
    const { data: matiere, error: matiereError } = await supabase
      .from("matieres")
      .select("id")
      .eq("id", matiere_id)
      .single();

    if (matiereError || !matiere) {
      return res.status(404).json({ error: "Matière introuvable." });
    }

    // Vérifier si le sujet appartient bien à la matière
    const { data: sujet, error: sujetError } = await supabase
      .from("sujets")
      .select("id, matiere_id")
      .eq("id", sujet_id)
      .single();

    if (sujetError || !sujet) {
      return res.status(404).json({ error: "Sujet introuvable." });
    }

    if (sujet.matiere_id !== matiere_id) {
      return res.status(400).json({
        error: "Ce sujet n'appartient pas à la matière spécifiée.",
      });
    }

    // Insertion de la question
    const { data, error } = await supabase
      .from("questions")
      .insert([
        {
          matiere_id,
          sujet_id,
          question,
          reponse,
          options: options || null,
        },
      ])
      .select();

    if (error) {
      console.error("Erreur Supabase :", error.message);
      return res.status(500).json({ error: "Erreur lors de l'insertion." });
    }

    return res.status(201).json({
      message: "Question ajoutée avec succès ✅",
      question: data[0],
    });
  } catch (err) {
    console.error("Erreur serveur :", err.message);
    return res.status(500).json({ error: "Erreur serveur interne." });
  }
});


// ---------------- ROUTES UTILISATEURS ----------------
app.get("/api/matieres", async (req, res) => {
  try {
    const { data, error } = await supabase.from("matieres").select("*");
    if (error) return res.status(400).json({ error });
    return res.json({ matieres: data });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get("/api/matieres/:id/questions", verifyToken, async (req, res) => {
  try {
    const matiere_id = req.params.id;
    const { data, error } = await supabase.from("questions").select("id, question, options, reponse").eq("matiere_id", matiere_id);
    if (error) return res.status(400).json({ error });
    return res.json({ questions: data });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// ---------------- ROUTE MY-MATIERES POUR UTILISATEUR ----------------
app.get("/api/my-matieres", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const { data: userMatieres, error: relError } = await supabase
      .from("user_matieres")
      .select("matiere_id")
      .eq("user_id", userId);

    if (relError) return res.status(400).json({ error: relError });

    const matiereIds = userMatieres.map(um => um.matiere_id);

    const { data: matieres, error } = await supabase
      .from("matieres")
      .select("*")
      .in("id", matiereIds);

    if (error) return res.status(400).json({ error });

    return res.json({ matieres });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// ---------------- CRUD CLASSES ----------------
app.get("/api/matieres/:id/classes", verifyToken, async (req, res) => {
  try {
    const matiere_id = req.params.id;
    const { data, error } = await supabase.from("classes").select("*").eq("matiere_id", matiere_id);
    if (error) return res.status(400).json({ error });
    return res.json({ classes: data });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/admin/matieres/:id/classes", verifyAdmin, async (req, res) => {
  try {
    const { nom } = req.body;
    const matiere_id = req.params.id;
    if (!nom) return res.status(400).json({ error: "Nom de classe requis" });

    const { data, error } = await supabase.from("classes").insert([{ matiere_id, nom }]).select();
    if (error) return res.status(500).json({ error });

    return res.status(201).json({ message: "Classe ajoutée", classe: data[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// Supprimer une question
app.delete("/api/admin/questions/:id", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from("questions").delete().eq("id", id);
    if (error) return res.status(400).json({ error });
    return res.json({ message: "Question supprimée" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});
app.get("/api/classes/:id/cours", verifyToken, async (req, res) => {
  try {
    const classe_id = req.params.id;
    const { data, error } = await supabase.from("cours").select("*").eq("classe_id", classe_id);
    if (error) return res.status(400).json({ error });
    return res.json({ cours: data });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/admin/classes/:id/cours", verifyAdmin, async (req, res) => {
  try {
    const { titre, contenu } = req.body;
    const classe_id = req.params.id;
    if (!titre || !contenu) return res.status(400).json({ error: "Titre et contenu requis" });

    const { data, error } = await supabase.from("cours").insert([{ classe_id, titre, contenu }]).select();
    if (error) return res.status(500).json({ error });

    return res.status(201).json({ message: "Cours ajouté", cours: data[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get("/api/cours/:id", verifyToken, async (req, res) => {
  try {
    const cours_id = req.params.id;
    const { data, error } = await supabase.from("cours").select("*").eq("id", cours_id).single();
    if (error) return res.status(404).json({ error: "Cours introuvable" });
    return res.json({ cours: data });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// ---------------- CRUD COURS ----------------

// Liste des cours d'une classe (déjà existant mais je le laisse pour clarté)
app.get("/api/classes/:id/cours", verifyToken, async (req, res) => {
  try {
    const classe_id = req.params.id;
    const { data, error } = await supabase
      .from("cours")
      .select("*")
      .eq("classe_id", classe_id);

    if (error) return res.status(400).json({ error });
    return res.json({ cours: data });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// Ajouter un cours
app.post("/api/admin/classes/:id/cours", verifyAdmin, async (req, res) => {
  try {
    const classe_id = req.params.id;
    const { titre, contenu } = req.body;

    if (!titre || !contenu) {
      return res.status(400).json({ error: "Titre et contenu requis" });
    }

    const { data, error } = await supabase
      .from("cours")
      .insert([{ classe_id, titre, contenu }])
      .select();

    if (error) return res.status(500).json({ error });

    return res
      .status(201)
      .json({ message: "Cours ajouté", cours: data[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// Modifier un cours
app.put("/api/admin/classes/:classeId/cours/:coursId", verifyAdmin, async (req, res) => {
  try {
    const { classeId, coursId } = req.params;
    const { titre, contenu } = req.body;

    const { data, error } = await supabase
      .from("cours")
      .update({ titre, contenu })
      .eq("id", coursId)
      .eq("classe_id", classeId)
      .select();

    if (error) return res.status(400).json({ error });
    if (!data.length) return res.status(404).json({ error: "Cours non trouvé" });

    return res.json({ message: "Cours modifié", cours: data[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// Supprimer un cours
app.delete("/api/admin/classes/:classeId/cours/:coursId", verifyAdmin, async (req, res) => {
  try {
    const { classeId, coursId } = req.params;

    const { error } = await supabase
      .from("cours")
      .delete()
      .eq("id", coursId)
      .eq("classe_id", classeId);

    if (error) return res.status(400).json({ error });

    return res.json({ message: "Cours supprimé" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// Modifier une question
app.put("/api/admin/questions/:id", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { question, reponse, options } = req.body;

    const { data, error } = await supabase
      .from("questions")
      .update({ question, reponse, options })
      .eq("id", id)
      .select();

    if (error) return res.status(400).json({ error });
    if (!data.length) return res.status(404).json({ error: "Question non trouvée" });

    return res.json({ message: "Question modifiée", question: data[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// Supprimer une question
app.delete("/api/admin/questions/:id", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const { error } = await supabase.from("questions").delete().eq("id", id);
    if (error) return res.status(400).json({ error });

    return res.json({ message: "Question supprimée" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// --- Route Paiement PayDunya (PAS de token requis)
// --- Route Paiement PayDunya (mode test)
app.post("/api/payment/paydunya/init", async (req, res) => {
  try {
    const { amount, description } = req.body;

    if (!amount || !description) {
      return res.status(400).json({ error: "Montant ou description manquant" });
    }

    // ✅ Construction de la requête vers PayDunya Sandbox
    const response = await fetch(
      "https://app.paydunya.com/api/v1/checkout-invoice/create",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "PAYDUNYA-MASTER-KEY": process.env.PAYDUNYA_MASTER_KEY,
          "PAYDUNYA-PRIVATE-KEY": process.env.PAYDUNYA_PRIVATE_KEY,
          "PAYDUNYA-PUBLIC-KEY": process.env.PAYDUNYA_PUBLIC_KEY,
          "PAYDUNYA-TOKEN": process.env.PAYDUNYA_TOKEN,
          "PAYDUNYA-MODE": "live", // ✅ Forcé en test
        },
        body: JSON.stringify({
          invoice: {
            items: [
              {
                name: "Paiement d'inscription MyChild",
                quantity: 1,
                unit_price: amount,
                total_price: amount,
                description,
              },
            ],
            total_amount: amount,
            description,
          },
          store: {
            name: "MyChild",
            tagline: "Éducation et sécurité des enfants",
            phone: "+22600000000",
            website_url: "https://mychildapp.com",
            postal_address: "Ouagadougou, Burkina Faso",
          },
          actions: {
            cancel_url: process.env.PAYDUNYA_CANCEL_URL,
            return_url: process.env.PAYDUNYA_RETURN_URL,
          },
        }),
      }
    );

    const data = await response.json();
    console.log(data);
    // ✅ Vérifie le retour PayDunya
    if (data?.response_code === "00") {
  return res.json({
    checkout_url: data.response_text, // ✅ ici au lieu de response_checkout_url
    token: data.token,
  });
} else {
  console.error("Erreur PayDunya:", data);
  return res
    .status(400)
    .json({ error: data.response_text || "Erreur PayDunya" });
}

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur PayDunya" });
  }
});

app.post("/api/payment/paydunya/callback", async (req, res) => {
  try {
    // PayDunya peut POST des infos. Souvent on reçoit un token dans body ou query.
    const token = req.body.token || req.query.token;
    if (!token) {
      // Si PayDunya poste tout le payload directement, tu peux parser ici
      console.warn("Callback reçu sans token, corps:", req.body);
      return res.status(400).send("Token manquant");
    }

    const pdBase = process.env.PAYDUNYA_BASE_URL || "https://app.paydunya.com/api";
    const headers = {
      "Content-Type": "application/json",
      "PAYDUNYA-PRIVATE-KEY": process.env.PAYDUNYA_PRIVATE_KEY,
      "PAYDUNYA-PUBLIC-KEY": process.env.PAYDUNYA_PUBLIC_KEY,
      "PAYDUNYA-TOKEN": process.env.PAYDUNYA_TOKEN,
    };

    // Vérifie l'état réel du paiement auprès de PayDunya
    const response = await axios.post(`${pdBase}/v1/checkout-invoice/confirm/${token}`, {}, { headers });
    const data = response.data.response;

    const transactionId = data?.custom_data?.transaction_id;
    const userId = data?.custom_data?.user_id;
    const status = data?.status;

    if (!transactionId) {
      console.error("Callback: pas de transactionId dans la réponse PayDunya", data);
      return res.status(400).send("Transaction introuvable");
    }

    // Met à jour les tables
    if (status === "completed" || status === "success" || status === "paid") {
      await supabase.from("payments").update({ status: "SUCCESS" }).eq("transaction_id", transactionId);
      await supabase.from("transactions").update({ status: "SUCCESS" }).eq("id", transactionId);

      if (userId) {
        await supabase.from("users").update({ hasPaid: true }).eq("id", userId);
      }

      return res.status(200).send("OK");
    } else {
      // status non complété
      await supabase.from("payments").update({ status }).eq("transaction_id", transactionId);
      await supabase.from("transactions").update({ status }).eq("id", transactionId);
      return res.status(200).send("Payment not completed");
    }
  } catch (err) {
    console.error("PayDunya callback error:", err.response?.data || err.message || err);
    return res.status(500).send("Erreur serveur callback");
  }
});

// ---------------- FINALIZE REGISTER (appelé après redirection return_url si tu veux créer l'utilisateur ici) ----------------
/**
 * /api/register/finalize
 * - Utilisé dans le flow où tu n'as pas créé l'utilisateur AVANT paiement.
 * - Reçoit formData et crée l'utilisateur maintenant que le paiement est réussi.
 */
app.post("/api/register/finalize", async (req, res) => {
  try {
    const { nom, prenom, phone, password, date_naissance, pays, nationalite, role, secretKey } = req.body;
    if (!nom || !prenom || !phone || !password) return res.status(400).json({ error: "Champs manquants" });

    // Vérifie existence
    const { data: existingUser } = await supabase
      .from("users")
      .select("id")
      .eq("phone", phone)
      .single();

    if (existingUser) {
      // Si existe déjà, on renvoie l'utilisateur et un token (login)
      const { data } = await supabase.from("users").select("*").eq("phone", phone).limit(1);
      const user = data[0];
      const token = jwt.sign({ id: user.id, phone: user.phone, role: user.role }, process.env.JWT_SECRET || "SECRET_KEY", { expiresIn: "7d" });
      return res.json({ message: "Utilisateur existe déjà", user, token });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    let finalRole = "user";
    if (role === "admin" && secretKey === process.env.ADMIN_SECRET) finalRole = "admin";

    const { data, error } = await supabase.from("users").insert([
      { nom, prenom, phone, password: hashedPassword, date_naissance, pays, nationalite, role: finalRole, hasPaid: true }
    ]).select();

    if (error) {
      console.error("register/finalize supabase error:", error);
      return res.status(500).json({ error: "Erreur base de données" });
    }

    const user = data[0];
    const token = jwt.sign({ id: user.id, phone: user.phone, role: user.role }, process.env.JWT_SECRET || "SECRET_KEY", { expiresIn: "7d" });

    return res.json({ message: "Utilisateur créé avec succès", user, token });
  } catch (err) {
    console.error("/api/register/finalize error:", err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/register-request", async (req, res) => {
  try {
    const { nom, prenom, phone, password, date_naissance, pays, nationalite, secretKey } = req.body;

    // ✅ Validation des champs
    if (!nom || !prenom || !phone || !password || !date_naissance || !pays || !nationalite) {
      return res.status(400).json({ error: "Tous les champs sont requis." });
    }

    // ✅ Validation du format du numéro
    const phoneRegex = /^\+\d{6,15}$/;
    if (!phoneRegex.test(phone)) {
      return res.status(400).json({ error: "Numéro de téléphone invalide." });
    }

    // ✅ Vérification du rôle (admin ou user)
    let role = "user";
    if (secretKey && secretKey === process.env.ADMIN_SECRET_KEY) {
      role = "admin";
    }

    // ✅ Vérifie si le numéro existe déjà dans users
    const { data: existingUser, error: userError } = await supabase
      .from("users")
      .select("id")
      .eq("phone", phone)
      .maybeSingle();

    if (userError) throw userError;
    if (existingUser) {
      return res.status(400).json({ error: "Ce numéro est déjà enregistré." });
    }

    // ✅ Vérifie si une demande en attente existe déjà
    const { data: existingRequest, error: requestError } = await supabase
      .from("register_requests")
      .select("id")
      .eq("phone", phone)
      .maybeSingle();

    if (requestError) throw requestError;
    if (existingRequest) {
      return res.status(400).json({ error: "Une demande est déjà en attente pour ce numéro." });
    }

    // ✅ Hash du mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);

    // ✅ Insertion dans register_requests
    const { data, error } = await supabase
      .from("register_requests")
      .insert([
        {
          nom,
          prenom,
          phone,
          password: hashedPassword,
          date_naissance,
          pays,
          nationalite,
          role,
          status: "pending",
        },
      ])
      .select()
      .single();

    if (error) throw error;

    return res.status(201).json({
      message: "Demande enregistrée avec succès.",
      request: data,
    });
  } catch (err) {
    console.error("Erreur lors de l'enregistrement :", err);
    return res.status(500).json({ error: "Erreur serveur. Veuillez réessayer plus tard." });
  }
});

// ===================== GESTION ADMIN : DEMANDES D'INSCRIPTION =====================

app.get("/api/admin/register-requests", verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("users")
      .select("*")
      .eq("pending_approval", true);

    if (error) return res.status(500).json({ error });
    res.json({ requests: data });
  } catch (err) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/admin/register-requests/:id/approve", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase
      .from("users")
      .update({ is_active: true, pending_approval: false, approved: true })
      .eq("id", id)
      .select();

    if (error) return res.status(500).json({ error });
    res.json({ message: "Utilisateur approuvé", user: data[0] });
  } catch (err) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});
app.post("/api/admin/register-requests/:id/reject", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from("users").delete().eq("id", id);
    if (error) return res.status(500).json({ error });
    res.json({ message: "Demande refusée et supprimée" });
  } catch (err) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/save-result", async (req, res) => {
  try {
    const { user_id, matiere_id, matiere, score, total, answers } = req.body;

    // Vérification des champs obligatoires
    if (!matiere || score == null || total == null || !answers) {
      return res.status(400).json({ error: "Champs manquants" });
    }

    // Vérification matiere_id
    const matiereIdInt = matiere_id ? parseInt(matiere_id, 10) : null;

    const percentage = Math.round((score / total) * 100);

    const { data, error } = await supabase
      .from("quiz_results")
      .insert([
        {
          user_id,               // UUID utilisateur
          matiere_id: matiereIdInt, // integer
          matiere,
          score,
          total,
          percentage,
          answers,               // JSONB
        },
      ])
      .select();

    if (error) throw error;

    return res.status(201).json({ message: "Résultat enregistré", result: data[0] });
  } catch (err) {
    console.error("Erreur API save-result:", err);
    return res.status(500).json({ error: "Erreur lors de l'enregistrement du résultat" });
  }
});



app.get("/api/results", async (req, res) => {
  const { data, error } = await supabase
    .from("quiz_results")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) return res.status(500).json({ error });
  return res.json(data);
});

// Activer un utilisateur
app.post("/api/admin/users/:id/activate", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabase
      .from("users")
      .update({ is_active: true })
      .eq("id", id)
      .select();

    if (error) return res.status(500).json({ error });
    if (!data.length) return res.status(404).json({ error: "Utilisateur non trouvé" });

    return res.json({ message: "Utilisateur activé", user: data[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// Désactiver un utilisateur
app.post("/api/admin/users/:id/deactivate", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabase
      .from("users")
      .update({ is_active: false })
      .eq("id", id)
      .select();

    if (error) return res.status(500).json({ error });
    if (!data.length) return res.status(404).json({ error: "Utilisateur non trouvé" });

    return res.json({ message: "Utilisateur désactivé", user: data[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});



/**
 * ➕ Ajouter un sujet pour une matière
 * POST /api/sujets
 * Body : { matiere_id, titre, description, ordre }
 */
app.post("/sujets", async (req, res) => {
  try {
    const { matiere_id, titre, description, ordre } = req.body;

    // Vérification des champs
    if (!matiere_id || !titre) {
      return res.status(400).json({
        error: "Le champ 'matiere_id' et 'titre' sont obligatoires.",
      });
    }

    // Vérifier si la matière existe
    const { data: matiere, error: matiereError } = await supabase
      .from("matieres")
      .select("*")
      .eq("id", matiere_id)
      .single();

    if (matiereError || !matiere) {
      return res.status(404).json({ error: "Matière introuvable." });
    }

    // Insertion du sujet
    const { data, error } = await supabase
      .from("sujets")
      .insert([
        {
          matiere_id,
          titre,
          description: description || null,
          ordre: ordre || 1,
        },
      ])
      .select();

    if (error) throw error;

    res.status(201).json({
      message: "Sujet ajouté avec succès ✅",
      sujet: data[0],
    });
  } catch (error) {
    console.error("Erreur ajout sujet:", error.message);
    res.status(500).json({ error: "Erreur interne du serveur." });
  }
});

/**
 * 📄 Lister tous les sujets d'une matière
 * GET /api/sujets/matiere/:matiere_id
 */
app.get("/api/sujets/matiere/:matiere_id", async (req, res) => {
  try {
    const { matiere_id } = req.params;

    const { data, error } = await supabase
      .from("sujets")
      .select("*")
      .eq("matiere_id", matiere_id)
      .order("ordre", { ascending: true });

    if (error) throw error;

    res.json(data);
  } catch (error) {
    console.error("Erreur récupération sujets:", error.message);
    res.status(500).json({ error: "Erreur interne du serveur." });
  }
});
// ---------------- SERVER ----------------
app.listen(PORT, () => console.log(`✅ API démarrée sur http://localhost:${PORT}`));
