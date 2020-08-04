class ExtendableError extends Error {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, ExtendableError.prototype);
    this.name = "ExtendableError";
    this.stack = (new Error(message)).stack;
  }
}

export interface HTTPErrorContent {
  code?: string;
  detail?: string;
}

export class HTTPError extends ExtendableError {
  public status: number;
  public content?: HTTPErrorContent;

  constructor(status: number, message: any, content?: HTTPErrorContent) {
    super(`${status} ${message}`);
    Object.setPrototypeOf(this, HTTPError.prototype);
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

export class EncryptionPasswordError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, EncryptionPasswordError.prototype);
    this.name = "EncryptionPasswordError";
  }
}

export class ProgrammingError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, ProgrammingError.prototype);
    this.name = "ProgrammingError";
  }
}

