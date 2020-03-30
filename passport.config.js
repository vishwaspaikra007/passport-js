const localStrategy = require('passport-local').Strategy

const bcrypt = require('bcrypt')

function initializePassport(passport, getUserByEmail, getUserById) {
    const authenticateUser = async (email, pwd, done) => {
        const user = getUserByEmail(email)

        if(user == null) {
            return done(null, false, { message: "no user with that email"})
        }

        try {
            if (await bcrypt.compare(pwd, user.pwd)) {
                return done(null, user)
            } else {
                return done(null, false, {message: "password incorrect"})
            }
        } catch (e){
            return done(e)
        }

    }

    passport.use(new localStrategy({
        usernameField: 'email',
        passwordField: 'pwd'
    }, authenticateUser))

    passport.serializeUser((user, done) => done(null, user.id))

    passport.deserializeUser((id, done) => {
        done(null, getUserById(id))
    })
}

module.exports = initializePassport