// This file is auto-generated by @hey-api/openapi-ts

export type BodyLoginForAccessTokenUsersLoginPost = {
  grant_type?: string | null;
  username: string;
  password: string;
  scope?: string;
  client_id?: string | null;
  client_secret?: string | null;
};

export type CreateUserForm = {
  username: string;
  email?: string | null;
  full_name?: string | null;
  password: string;
  password_repeat: string;
};

export type HttpValidationError = {
  detail?: Array<ValidationError>;
};

export type Token = {
  access_token: string;
  token_type: string;
};

export type UpdateUserForm = {
  username: string;
  email?: string | null;
  full_name?: string | null;
  password?: string | null;
  password_repeat?: string | null;
};

export type UserResponse = {
  username: string;
  email?: string | null;
  full_name?: string | null;
};

export type ValidationError = {
  loc: Array<string | number>;
  msg: string;
  type: string;
};

export type RootGetData = {
  body?: never;
  path?: never;
  query?: never;
  url: '/';
};

export type RootGetResponses = {
  /**
   * Successful Response
   */
  200: unknown;
};

export type RegisterNewUserUsersRegisterPostData = {
  body: CreateUserForm;
  path?: never;
  query?: never;
  url: '/users/register';
};

export type RegisterNewUserUsersRegisterPostErrors = {
  /**
   * Validation Error
   */
  422: HttpValidationError;
};

export type RegisterNewUserUsersRegisterPostError =
  RegisterNewUserUsersRegisterPostErrors[keyof RegisterNewUserUsersRegisterPostErrors];

export type RegisterNewUserUsersRegisterPostResponses = {
  /**
   * Successful Response
   */
  200: UserResponse;
};

export type RegisterNewUserUsersRegisterPostResponse =
  RegisterNewUserUsersRegisterPostResponses[keyof RegisterNewUserUsersRegisterPostResponses];

export type LoginForAccessTokenUsersLoginPostData = {
  body: BodyLoginForAccessTokenUsersLoginPost;
  path?: never;
  query?: never;
  url: '/users/login';
};

export type LoginForAccessTokenUsersLoginPostErrors = {
  /**
   * Validation Error
   */
  422: HttpValidationError;
};

export type LoginForAccessTokenUsersLoginPostError =
  LoginForAccessTokenUsersLoginPostErrors[keyof LoginForAccessTokenUsersLoginPostErrors];

export type LoginForAccessTokenUsersLoginPostResponses = {
  /**
   * Successful Response
   */
  200: Token;
};

export type LoginForAccessTokenUsersLoginPostResponse =
  LoginForAccessTokenUsersLoginPostResponses[keyof LoginForAccessTokenUsersLoginPostResponses];

export type GetCurrentUserInfoUsersInfoGetData = {
  body?: never;
  path?: never;
  query?: never;
  url: '/users/info';
};

export type GetCurrentUserInfoUsersInfoGetResponses = {
  /**
   * Successful Response
   */
  200: UserResponse;
};

export type GetCurrentUserInfoUsersInfoGetResponse =
  GetCurrentUserInfoUsersInfoGetResponses[keyof GetCurrentUserInfoUsersInfoGetResponses];

export type UpdateUserInfoUsersUpdatePatchData = {
  body: UpdateUserForm;
  path?: never;
  query?: never;
  url: '/users/update';
};

export type UpdateUserInfoUsersUpdatePatchErrors = {
  /**
   * Validation Error
   */
  422: HttpValidationError;
};

export type UpdateUserInfoUsersUpdatePatchError =
  UpdateUserInfoUsersUpdatePatchErrors[keyof UpdateUserInfoUsersUpdatePatchErrors];

export type UpdateUserInfoUsersUpdatePatchResponses = {
  /**
   * Successful Response
   */
  200: UserResponse;
};

export type UpdateUserInfoUsersUpdatePatchResponse =
  UpdateUserInfoUsersUpdatePatchResponses[keyof UpdateUserInfoUsersUpdatePatchResponses];

export type ClientOptions = {
  baseUrl: `${string}://${string}/api/v1` | (string & {});
};
