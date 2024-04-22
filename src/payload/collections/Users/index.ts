import type { CollectionConfig } from 'payload/types'

import { admins } from '../../access/admins'
import { anyone } from '../../access/anyone'
import adminsAndUser from './access/adminsAndUser'
import { checkRole } from './checkRole'
import { ensureFirstUserIsAdmin } from './hooks/ensureFirstUserIsAdmin'
import { loginAfterCreate } from './hooks/loginAfterCreate'
import payload from 'payload'
import twilio from 'twilio';
import jwt from 'jsonwebtoken'

const { TWILIO_AUTH_TOKEN, TWILIO_ACCOUNT_SID, TWILIO_SERVICE_SID, JWT_SECRET } = process.env


function generateJWT(phoneNumber) {
  return jwt.sign({phoneNumber}, JWT_SECRET, {expiresIn: '1h'})
}

const Users: CollectionConfig = {
  slug: 'users',
  fields: [
    {
      name: 'name',
      type: 'text',
      required: true,
    },
    {
      name: 'email',
      type: 'text',
      required: true,
    },
    {
      name: 'phoneNumber',
      type: 'text',
      required: true,
    },
    // {
    //   name: 'otp',
    //   type: 'text',
    //   access: {
    //     create: () => true,
    //     read: () => false,
    //     update: () => false,
    //   }
    // },
    // {
    //   name: 'otpExpiry',
    //   type: 'text',
    //   access: {
    //     create: () => true,
    //     read: () => false,
    //     update: () => false,
    //   }
    // },
    {
      name: 'otpAttempts',
      type: 'number',
      access: {
        create: () => true,
        read: () => false,
        update: () => false,
      }
    }
  ],
  endpoints: [
    {
      path: '/register',
      method: 'post',
      handler: async (req, res) => {
        const { name, email, countryCode, phoneNumber } = req.body;

        try {
          const formattedPhoneNumber = `${countryCode}${phoneNumber}`

          const existingUser = await payload.find({
            collection: 'users',
            where: {
              phoneNumber: {
                equals: formattedPhoneNumber
              }
            },
            limit: 1
          })

          if (existingUser.totalDocs > 0) {
            return res.status(409).json({ message: "This number is already in use" });
          }

          const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

          const verify = await client
            .verify
            .v2
            .services(TWILIO_SERVICE_SID)
            .verifications
            .create({
              to: formattedPhoneNumber,
              channel: 'sms'
            })

          console.log(verify)

          const otpExpiry = new Date(Date.now() + 30 * 1000)

          let user;

          user = await payload.create({
            collection: 'users',
            data: {
              name,
              email,
              phoneNumber: formattedPhoneNumber,
              otpAttempts: 0,
            }
          })


          res.status(201).json({
            message: "User registered and OTP sent.",
            user,
            otpSession: verify,
          })
        } catch (error) {
          console.log("OTP error: " + error)
          res.status(500).json({
            message: 'Error while generating OTP',
          })
        }
      }
    },
    {
      path: '/login',
      method: 'post',
      handler: async (req, res) => { 
        const { countryCode, phoneNumber } = req.body;
        const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

        try {
          const formattedPhoneNumber = `${countryCode}${phoneNumber}`

          const existingUser = await payload.find({
            collection: 'users',
            where: {
              phoneNumber: {
                equals: formattedPhoneNumber
              }
            },
            limit: 1
          }) 

          if (existingUser.totalDocs === 0) {
            return res.status(404).json({ message: "User not found." });
          }

          const verification = await client.verify.v2.services(process.env.TWILIO_SERVICE_SID)
            .verifications
            .create({ to: formattedPhoneNumber, channel: 'sms' });

          res.status(200).json({
            message: "OTP sent for login verification.",
            otpSession: verification.sid
          });
        } catch (error) {
          console.error("Login OTP error: " + error);
          res.status(500).json({
            message: 'Error in login OTP generation',
          });
        }
      }
    },
    {
      path: '/verify-otp',
      method: 'post',
      handler: async (req, res) => {
        const { countryCode, phoneNumber, code } = req.body;
        const formattedPhoneNumber = `${countryCode}${phoneNumber}`

        const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

        try {
          const verificationCheck = await client.verify.v2.services(TWILIO_SERVICE_SID)
            .verificationChecks
            .create({
              to: formattedPhoneNumber,
              code: code
            })

          if (verificationCheck.status === 'approved') {
            const token = generateJWT(formattedPhoneNumber);

            res.cookie('session_token', token, {
              httpOnly: true,
              secure: false,
              maxAge: 3600 * 1000,
              // sameSite: 
            })

            return res.status(200).json({
              message: "OTP verified successfully",
              verificationCheck,
              token: token
            });
          } else {
            return res.status(404).json({
              message: "Invalid OTP"
            })
          }
          
          
        }
        catch (error) {
          console.error("OTP Verification error: " + error);
          res.status(500).json({
            message: 'Error during OTP verification',
            error: error.message
          });
        }
      }
    },
    {
      path: '/logout',
      method: 'post',
      handler: async (req, res) => { 
        try {
          res.clearCookie('session_token');

          res.status(200).json({
            message: "Logged out successfully"
          })
        } catch (error) {
          console.error("Logout error: " + error);
          res.status(500).json({
            message: 'Error during logout',
          });
        }
      }
    }
  ]
}

export default Users
