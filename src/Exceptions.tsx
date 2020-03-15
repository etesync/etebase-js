class ExtendableError extends Error {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, ExtendableError.prototype);
    this.name = 'ExtendableError';
    this.stack = (new Error(message)).stack;
  }
}

export class HTTPError extends ExtendableError {
  public status: number;

  constructor(status: number, message: any) {
    super(message);
    Object.setPrototypeOf(this, HTTPError.prototype);
    this.name = 'HTTPError';

    this.status = status;
  }
}

export class NetworkError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, NetworkError.prototype);
    this.name = 'NetworkError';
  }
}

export class IntegrityError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, IntegrityError.prototype);
    this.name = 'IntegrityError';
  }
}

export class EncryptionPasswordError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, EncryptionPasswordError.prototype);
    this.name = 'EncryptionPasswordError';
  }
}

