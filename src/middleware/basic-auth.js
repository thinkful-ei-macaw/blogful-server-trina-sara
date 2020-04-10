//const bcrypt = require('bcryptjs')
const AuthService = require('../auth/auth-service'
)
function requireAuth(req, res, next) {

  const authToken = req.get('Authorization') || ''; //checking request header for auth attr
  let basicToken

  if (!authToken.toLowerCase().startsWith('basic')) {
    return res.status(401).json({ error: 'Missing basic token'
    })
  }
  else {
    basicToken = authToken.slice('basic '.length, authToken.length); //parse token from label(basic)
  }

  const [tokenUserName, tokenPassword] = Buffer //destruct pw and un from basictoken
    .from(basicToken, 'base64')
    .toString()
    .split(':')

    if (!tokenUserName || !tokenPassword) {
      return res.status(401).json({ error: 'Unauthorized request' })
    }

    req.app.get('db')('blogful_users')
      .where({ user_name: tokenUserName }) //gets user data from user table
      .first()
      .then(user => {

        if (!user) {
          return res.status(401).json({ error: 'Unauthorized request' })
        }

        return AuthService.comparePasswords(tokenPassword, user.password) //checks (encrytped)pw is equal to pw stored in table
          .then(passwordsMatch => {
            if (!passwordsMatch) {
              return res.status(401).json({
                error: 'Unauthorized request' 
              })
            }
            req.user = user
            next()
          })
      })
      .catch(next)
}

module.exports = {
  requireAuth,
}
