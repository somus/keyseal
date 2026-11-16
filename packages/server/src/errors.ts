/**
 * Thrown from `onCompleted` to refuse the result: the job fails with
 * `message`, which the helper gets with a 422 and the page in `status`.
 */
export class JobRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JobRefused";
  }
}

/**
 * Thrown by `createSignJob` and `createEnrolJob` for input that breaks one
 * of their limits; `message` says which. It is still a `TypeError`, and its
 * class tells it apart from one an adapter throws, such as a failed `fetch`.
 */
export class InvalidJobInput extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidJobInput";
  }
}
