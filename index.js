import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import helmet from "helmet";
import morgan from "morgan";
import path from "path";
import { fileURLToPath } from "url";

import { register } from "./controllers/authController.js";
import authRoutes from "./routes/authRoutes.js";

/* CONFIGURATIONS */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config();
const app = express();
app.use(express.json());
app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" }));
app.use(morgan("common"));
app.use(bodyParser.json({ limit: "30mb", extended: true }));
app.use(bodyParser.urlencoded({ limit: "30mb", extended: true }));
app.use(cors());
app.use("/assets", express.static(path.join(__dirname, "public/assets")));

const PORT = process.env.PORT || 3031;
const DB = process.env.DB;

/* FILE STORAGE */
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, "public/assets");
    },
    fileName: function (req, file, cb) {
        cb(null, file.originalname);
    },
});

const upload = multer({ storage });

/* ROUTES WITH FILES */
app.post("/auth/register", upload.single("picture"), register);

/* ROUTES */
app.use("/api/auth", authRoutes);

/* MONGOOSE SETUP */
mongoose
    .connect(DB.replace("<password>", process.env.DB_PASSWORD), {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Server is running on PORT ${PORT}`);
        });
    })
    .catch((err) => {
        console.log(err);
    });
