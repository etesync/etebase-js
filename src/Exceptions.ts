class ExtendableError extends Error {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, ExtendableError.prototype);
    this.name = "ExtendableError";
    this.stack = (new Error(message)).stack;
  }
}

export interface HttpFieldErrors {
  code: string;
  detail: string;
  field?: string;
}

export interface HttpErrorContent {
  code?: string;
  detail?: string;
  errors?: HttpFieldErrors[];
}

export class HttpError extends ExtendableError {
  public status: number;
  public content?: HttpErrorContent;

  constructor(status: number, message: any, content?: HttpErrorContent) {
    super(`${status} ${message}`);
    Object.setPrototypeOf(this, HttpError.prototype);
    this.name = "HTTPError";

    this.status = status;
    this.content = content;
  }
}

export class NetworkError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, NetworkError.prototype);
    this.name = "NetworkError";
  }
}

export class IntegrityError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, IntegrityError.prototype);
    this.name = "IntegrityError";
  }
}

export class MissingContentError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, MissingContentError.prototype);
    this.name = "MissingContentError";
  }
}

export class UnauthorizedError extends ExtendableError {
  public content?: HttpErrorContent;
  constructor(message: any, content?: HttpErrorContent) {
    super(message);
    Object.setPrototypeOf(this, UnauthorizedError.prototype);
    this.name = "UnauthorizedError";

    this.content = content;
  }
}

export class PermissionDeniedError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, PermissionDeniedError.prototype);
    this.name = "PermissionDeniedError";
  }
}

export class ConflictError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, ConflictError.prototype);
    this.name = "ConflictError";
  }
}

export class NotFoundError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, NotFoundError.prototype);
    this.name = "NotFoundError";
  }
}

export class TemporaryServerError extends HttpError {
  constructor(status: number, message: any, content?: HttpErrorContent) {
    super(status, message, content);
    Object.setPrototypeOf(this, TemporaryServerError.prototype);
    this.name = "TemporaryServerError";
  }
}

export class ServerError extends HttpError {
  constructor(status: number, message: any, content?: HttpErrorContent) {
    super(status, message, content);
    Object.setPrototypeOf(this, ServerError.prototype);
    this.name = "ServerError";
  }
}

export class ProgrammingError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, ProgrammingError.prototype);
    this.name = "ProgrammingError";
  }
}

