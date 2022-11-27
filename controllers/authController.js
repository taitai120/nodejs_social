import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

/* SIGN TOKEN */
const signToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET);
};

/* REGISTER USER */
export const register = async (req, res) => {
    try {
        const {
            firstName,
            lastName,
            email,
            password,
            picturePath,
            friends,
            location,
            occupation,
        } = req.body;

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const newUser = await User.create({
            firstName,
            lastName,
            email,
            password: passwordHash,
            picturePath,
            friends,
            location,
            occupation,
            viewedProfile: Math.floor(Math.random() * 10000),
            impressions: Math.floor(Math.random() * 10000),
        });

        const token = signToken(newUser._id);

        res.status(201).json({
            status: "success",
            data: {
                newUser,
            },
            token,
        });
    } catch (error) {
        return res.status(500).json({
            status: "fail",
            error: error.message,
        });
    }
};

/* LOGIN USER */
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email }).select("+password");

        if (!user) {
            return res.status(400).json({
                status: "fail",
                message:
                    "The user with this email doesn't exist. Please try again.",
            });
        }

        if (!(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({
                status: "fail",
                message: "Password is invalid. Please try again.",
            });
        }

        const token = signToken(user._id);

        user.password = undefined;

        res.status(200).json({
            status: "success",
            data: {
                user,
            },
            token,
        });
    } catch (error) {
        return res.status(500).json({
            status: "fail",
            error: error.message,
        });
    }
};
