import { BaseController } from '@/controllers/base.controller';
import { AppError } from '@/utils/appError';
import { ErrorCode } from '@/utils/errorCodes';
import { ENV } from '@/config/env';
import type { Request, Response, NextFunction } from 'express';
import type { ClientService } from '@/services/client.service';
import type { JoseService } from '@/services/jose.service';
import type { UserService } from '@/services/user.service';
import { ROLES } from '@/utils/constant';

export class ClientController extends BaseController {
  constructor(
    private clientService: ClientService,
    private joseService: JoseService,
    private userService: UserService,
  ) {
    super();
  }

  // ---------------- ADD CLIENT ----------------

  addClient = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const { name, slug, client_type, redirect_uri } = req.body;

      if (!this.clientService.isValidSlug(slug)) {
        throw new AppError('Invalid domain', 400, ErrorCode.INVALID_DOMAIN);
      }

      const domain = this.clientService.getClientDomain(slug);

      const data = await this.clientService.createClient({
        userId: req.user.id,
        name,
        domain,
        redirectURI: redirect_uri,
        clientType: client_type,
      });

      /**
       * TODO: fix later
       * One-time flash cookie
       * here we want to send secret to render client controller
       * as of now this is one of the most safest way i discovered
       */
      res.cookie('__flash_client_secret', data.clientSecret, {
        httpOnly: true,
        secure: ENV.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 60 * 1000, // 1 minute
      });

      // If user is creating first client assign developer role
      const roles = req.user.roles;
      if (!roles.includes(ROLES.DEVELOPER)) {
        await this.userService.update(req.user.id, {
          roles: [...roles, ROLES.DEVELOPER],
          updatesAt: new Date(),
        });
      }

      return {
        data,
        message: 'New client registered successfully',
        successRedirect: `/client/${data.id}`,
      };
    });
  };

  // -------------------- MANAGE REDIRECT URIS -------------------

  manageRedirects = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const { client_id } = req.params;
      const { action, redirect_uri } = req.body;

      if (action !== 'add' && action !== 'del') {
        throw new AppError('Invalid action. Must be add or del', 400, ErrorCode.INVALID_REQUEST);
      }

      const client = await this.clientService.getClient(client_id);
      const normalizedURI = this.clientService.normalizeAndValidateURI(redirect_uri);
      const isExistingURI = client.redirectURIs.includes(normalizedURI);

      let data;

      if (action === 'add') {
        if (isExistingURI) {
          throw new AppError('Redirect URI already exists', 400, ErrorCode.INVALID_REDIRECT_URI);
        }

        data = await this.clientService.addRedirectURI({
          clientId: client_id,
          normalizedURI,
          existingRedirectURIs: client.redirectURIs,
        });
      } else if (action === 'del') {
        if (!isExistingURI) {
          throw new AppError('Redirect URI does not exist', 400, ErrorCode.INVALID_REDIRECT_URI);
        }

        data = await this.clientService.deleteRedirectURI({
          clientId: client_id,
          normalizedURI,
          existingRedirectURIs: client.redirectURIs,
        });
      }

      return {
        data,
        message: `Redirect URI ${action === 'add' ? 'added' : 'removed'} successfully`,
        successRedirect: `/client/${client_id}`,
      };
    });
  };

  // -------------------- GET CLIENT -------------------

  getClient = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const { client_id } = req.params;

      const client = await this.clientService.getClient(client_id);

      return {
        data: client,
        message: `Client info set successfully`,
        successRedirect: '/',
      };
    });
  };

  // ---------------- ROTATE SECRET ----------------

  rotateClientSecret = (req: Request, res: Response, next: NextFunction) => {
    this.handleRequest(req, res, next, async () => {
      const { client_id } = req.body;

      const data = await this.clientService.rotateClientSecret(client_id);

      /**
       * TODO: fix later
       * One-time flash cookie
       * here we want to send secret to render client controller
       * as of now this is one of the most safest way i discovered
       */
      res.cookie('__flash_client_secret', data.clientSecret, {
        httpOnly: true,
        secure: ENV.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 60 * 1000, // 1 minute
      });

      return {
        data,
        message: 'Client secret rotated successfully',
        successRedirect: `/client/${client_id}`,
      };
    });
  };

  // -------- DEACTIVATE --------

  deactivate = (req: Request, res: Response, next: NextFunction) => {
    this.handleRequest(req, res, next, async () => {
      await this.clientService.update(req.params.client_id, { isActive: false, revokedAt: new Date() });

      return {
        message: 'Client deactivated successfully',
        successRedirect: `/client/${req.params.client_id}`,
      };
    });
  };

  // -------- ACTIVATE --------
  activate = (req: Request, res: Response, next: NextFunction) => {
    this.handleRequest(req, res, next, async () => {
      await this.clientService.activate(req.params.client_id);

      return {
        message: 'Client activated successfully',
        successRedirect: `/client/${req.params.client_id}`,
      };
    });
  };

  // -------- DELETE --------

  delete = (req: Request, res: Response, next: NextFunction) => {
    this.handleRequest(req, res, next, async () => {
      await this.clientService.delete(req.params.client_id);

      return {
        message: 'Client deleted permanently',
        successRedirect: `/account`,
      };
    });
  };

  // ---------------- JWKS ----------------

  getJwks = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(
      req,
      res,
      next,
      async () => {
        const jwks = await this.joseService.getJwks();
        res.status(200).json({ keys: jwks.keys });
      },
      { raw: true },
    );
  };
}
