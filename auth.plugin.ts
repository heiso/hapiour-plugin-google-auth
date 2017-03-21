import { Server, Request, IReply } from 'hapi'
import { Plugin, IPlugin, IPluginOptions } from 'hapiour-decorators'
import * as hapiAuthJwt2 from 'hapi-auth-jwt2'
import * as Config from 'config'
import * as JWT from 'jsonwebtoken'
import * as hapiAuthGoogle from 'hapi-auth-google'

@Plugin({
  name: 'HapiourGoogleAuthPlugin',
  version: '0.1.0'
})
export class HapiourGoogleAuthPlugin implements IPlugin {

  public static isAuthorized(token: any): boolean {
    return token.id === Config.get('security.allowedToken')
  }

  private googleAuthOptions: IPluginOptions

  public constructor() {
    this.googleAuthOptions = {
      access_type: 'online',
      approval_prompt: 'auto',
      scope: 'https://www.googleapis.com/auth/plus.profile.emails.read',
      BASE_URL: Config.get('security.baseUrl'),
      REDIRECT_URL: Config.get('security.redirectUrl'),
      GOOGLE_CLIENT_ID: Config.get('security.clientId'),
      GOOGLE_CLIENT_SECRET: Config.get('security.clientSecret'),
      handler: this.googleAuthHandler
    }
  }

  public register(server: Server, options: IPluginOptions, next: () => void): void {
    server.register([hapiAuthJwt2, {register: hapiAuthGoogle, options: this.googleAuthOptions}], () => {
      server.auth.strategy('jwt', 'jwt', true, {
        key: Config.get('security.jwtSecret'),
        validateFunc: (decoded, request, callback) => {
          return callback(null, HapiourGoogleAuthPlugin.isAuthorized(decoded))
        },
        verifyOptions: {
          ignoreExpiration: true
        }
      })
      this.initRouting(server)
      next()
    })
    
  }

  private initRouting(server: Server): void {
    server.route({
      method: '*',
      path: '/',
      config: {
        auth: {
          mode: 'try',
          strategies: ['jwt']
        }
      },
      handler: (request: Request, reply: IReply): void => {
        if (!request.auth.isAuthenticated) {
          reply.redirect('/login')
        } else {
          reply('<pre>' + JSON.stringify(request.auth) + '</pre>')
        }
      }
    })

    server.route({
      method: 'GET',
      path: '/login',
      config: {
        auth: false
      },
      handler: (request: Request, reply: IReply): void => {
        reply('<a href="' + (<any>request.server).generate_google_oauth2_url() + '">Login</a>')
      }
    })
  }

  private googleAuthHandler(request: Request, reply: IReply, tokens: any, profile: any): any {
    if (profile) {
      let token = {
        fistname: profile.name.givenName,
        lastname: profile.name.familyName,
        image: profile.image.url,
        id: profile.id,
        email: profile.emails[0],
        agent: request.headers['user-agent']
      }

      if (HapiourGoogleAuthPlugin.isAuthorized(token)) {
        let jwt = JWT.sign(token, <string>Config.get('security.jwtSecret'))
        profile.tokens = tokens
        profile.valid = true
        reply('Authentication successful')
          .state('token', jwt, {
            isHttpOnly: false,
            isSecure: false
          })
          .redirect('/')
      } else {
        reply('Not authorized.').code(403)
      }
    }
    else {
      reply('Sorry, something went wrong, please try again.')
    }
  }

}
