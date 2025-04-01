// This file is auto-generated by @hey-api/openapi-ts

export type AudioAltFile = {
  url: string;
  bit_rate: number;
  filesize: number;
  filetype: string;
  sample_rate: number;
};

export type AudioCategory =
  | 'audiobook'
  | 'music'
  | 'news'
  | 'podcast'
  | 'pronunciation'
  | 'sound_effect';

export const AudioCategory = {
  AUDIOBOOK: 'audiobook',
  MUSIC: 'music',
  NEWS: 'news',
  PODCAST: 'podcast',
  PRONUNCIATION: 'pronunciation',
  SOUND_EFFECT: 'sound_effect',
} as const;

export type AudioLength = 'long' | 'medium' | 'short' | 'shortest';

export const AudioLength = {
  LONG: 'long',
  MEDIUM: 'medium',
  SHORT: 'short',
  SHORTEST: 'shortest',
} as const;

export type AudioSearchItem = {
  id: string;
  title: string | null;
  indexed_on: Date;
  foreign_landing_url: string | null;
  url: string | null;
  creator: string | null;
  creator_url: string | null;
  license: string;
  license_version: string | null;
  license_url: string | null;
  provider: string | null;
  source: string | null;
  category: string | null;
  genres: Array<string> | null;
  filesize: number | null;
  filetype: string | null;
  tags: Array<MediaTag> | null;
  alt_files: Array<AudioAltFile> | null;
  attribution: string | null;
  fields_matched: Array<string> | null;
  mature: boolean;
  audio_set: AudioSet | null;
  duration: number | null;
  bit_rate: number | null;
  sample_rate: number | null;
  thumbnail: string | null;
  detail_url: string;
  related_url: string;
  waveform: string;
};

export type AudioSearchResponse = {
  result_count: number;
  page_count: number;
  page_size: number;
  page: number;
  results: Array<AudioSearchItem>;
  warnings?: Array<{
    [key: string]: unknown;
  }> | null;
};

export type AudioSet = {
  title: string | null;
  foreign_landing_url: string | null;
  creator: string | null;
  creator_url: string | null;
  url: string | null;
  filesize: number | null;
  filetype: string | null;
};

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

export type EmailRequest = {
  email: string;
};

export type EmailVerificationStatus = 'verified' | 'verifying' | 'none';

export const EmailVerificationStatus = {
  VERIFIED: 'verified',
  VERIFYING: 'verifying',
  NONE: 'none',
} as const;

export type HttpValidationError = {
  detail?: Array<ValidationError>;
};

export type ImageAspectRatio = 'square' | 'tall' | 'wide';

export const ImageAspectRatio = {
  SQUARE: 'square',
  TALL: 'tall',
  WIDE: 'wide',
} as const;

export type ImageCategory = 'digitized_artwork' | 'illustration' | 'photograph';

export const ImageCategory = {
  DIGITIZED_ARTWORK: 'digitized_artwork',
  ILLUSTRATION: 'illustration',
  PHOTOGRAPH: 'photograph',
} as const;

export type ImageSearchItem = {
  id: string;
  title: string | null;
  indexed_on: Date;
  foreign_landing_url: string | null;
  url: string | null;
  creator: string | null;
  creator_url: string | null;
  license: string;
  license_version: string | null;
  license_url: string | null;
  provider: string | null;
  source: string | null;
  category: string | null;
  filesize: number | null;
  filetype: string | null;
  tags: Array<MediaTag> | null;
  attribution: string | null;
  fields_matched: Array<string> | null;
  mature: boolean;
  height: number | null;
  width: number | null;
  thumbnail: string;
  detail_url: string;
  related_url: string;
};

export type ImageSearchResponse = {
  result_count: number;
  page_count: number;
  page_size: number;
  page: number;
  results: Array<ImageSearchItem>;
  warnings?: Array<{
    [key: string]: unknown;
  }> | null;
};

export type ImageSize = 'large' | 'medium' | 'small';

export const ImageSize = {
  LARGE: 'large',
  MEDIUM: 'medium',
  SMALL: 'small',
} as const;

export type MediaHistoryResponse = {
  keyword: string;
  timestamp: Date;
};

export type MediaLicense =
  | 'by'
  | 'by-nc'
  | 'by-nc-nd'
  | 'by-nc-sa'
  | 'by-nd'
  | 'by-sa'
  | 'cc0'
  | 'nc-sampling+'
  | 'pdm'
  | 'sampling+';

export const MediaLicense = {
  BY: 'by',
  BY_NC: 'by-nc',
  BY_NC_ND: 'by-nc-nd',
  BY_NC_SA: 'by-nc-sa',
  BY_ND: 'by-nd',
  BY_SA: 'by-sa',
  CC0: 'cc0',
  'NC_SAMPLING+': 'nc-sampling+',
  PDM: 'pdm',
  'SAMPLING+': 'sampling+',
} as const;

export type MediaLicenseType = 'all' | 'all-cc' | 'commercial' | 'modification';

export const MediaLicenseType = {
  ALL: 'all',
  ALL_CC: 'all-cc',
  COMMERCIAL: 'commercial',
  MODIFICATION: 'modification',
} as const;

export type MediaTag = {
  accuracy: number | null;
  name: string;
  unstable__provider: string | null;
};

export type MediaType = 'image' | 'audio';

export const MediaType = {
  IMAGE: 'image',
  AUDIO: 'audio',
} as const;

export type PasswordResetForm = {
  password: string;
  password_repeat: string;
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
  email_verification_status: EmailVerificationStatus;
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

export type RefreshAccessTokenUsersRefreshPostData = {
  body?: never;
  path?: never;
  query?: never;
  url: '/users/refresh';
};

export type RefreshAccessTokenUsersRefreshPostErrors = {
  /**
   * Validation Error
   */
  422: HttpValidationError;
};

export type RefreshAccessTokenUsersRefreshPostError =
  RefreshAccessTokenUsersRefreshPostErrors[keyof RefreshAccessTokenUsersRefreshPostErrors];

export type RefreshAccessTokenUsersRefreshPostResponses = {
  /**
   * Successful Response
   */
  200: Token;
};

export type RefreshAccessTokenUsersRefreshPostResponse =
  RefreshAccessTokenUsersRefreshPostResponses[keyof RefreshAccessTokenUsersRefreshPostResponses];

export type LogoutUsersLogoutDeleteData = {
  body?: never;
  path?: never;
  query?: never;
  url: '/users/logout';
};

export type LogoutUsersLogoutDeleteResponses = {
  /**
   * Successful Response
   */
  200: unknown;
};

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

export type VerifyEmailUsersVerifyEmailGetData = {
  body?: never;
  path?: never;
  query: {
    token: string;
  };
  url: '/users/verify-email';
};

export type VerifyEmailUsersVerifyEmailGetErrors = {
  /**
   * Validation Error
   */
  422: HttpValidationError;
};

export type VerifyEmailUsersVerifyEmailGetError =
  VerifyEmailUsersVerifyEmailGetErrors[keyof VerifyEmailUsersVerifyEmailGetErrors];

export type VerifyEmailUsersVerifyEmailGetResponses = {
  /**
   * Successful Response
   */
  200: UserResponse;
};

export type VerifyEmailUsersVerifyEmailGetResponse =
  VerifyEmailUsersVerifyEmailGetResponses[keyof VerifyEmailUsersVerifyEmailGetResponses];

export type SendVerificationEmailUsersVerifyEmailPostData = {
  body?: never;
  path?: never;
  query?: never;
  url: '/users/verify-email';
};

export type SendVerificationEmailUsersVerifyEmailPostResponses = {
  /**
   * Successful Response
   */
  200: UserResponse;
};

export type SendVerificationEmailUsersVerifyEmailPostResponse =
  SendVerificationEmailUsersVerifyEmailPostResponses[keyof SendVerificationEmailUsersVerifyEmailPostResponses];

export type ResetPasswosdUsersResetPasswordPatchData = {
  body: PasswordResetForm;
  path?: never;
  query: {
    token: string;
  };
  url: '/users/reset-password';
};

export type ResetPasswosdUsersResetPasswordPatchErrors = {
  /**
   * Validation Error
   */
  422: HttpValidationError;
};

export type ResetPasswosdUsersResetPasswordPatchError =
  ResetPasswosdUsersResetPasswordPatchErrors[keyof ResetPasswosdUsersResetPasswordPatchErrors];

export type ResetPasswosdUsersResetPasswordPatchResponses = {
  /**
   * Successful Response
   */
  200: UserResponse;
};

export type ResetPasswosdUsersResetPasswordPatchResponse =
  ResetPasswosdUsersResetPasswordPatchResponses[keyof ResetPasswosdUsersResetPasswordPatchResponses];

export type SendResetPasswordEmailUsersResetPasswordPostData = {
  body: EmailRequest;
  path?: never;
  query?: never;
  url: '/users/reset-password';
};

export type SendResetPasswordEmailUsersResetPasswordPostErrors = {
  /**
   * Validation Error
   */
  422: HttpValidationError;
};

export type SendResetPasswordEmailUsersResetPasswordPostError =
  SendResetPasswordEmailUsersResetPasswordPostErrors[keyof SendResetPasswordEmailUsersResetPasswordPostErrors];

export type SendResetPasswordEmailUsersResetPasswordPostResponses = {
  /**
   * Successful Response
   */
  200: unknown;
};

export type SearchMediaMediaSearchGetData = {
  body?: never;
  path?: never;
  query: {
    type: MediaType;
    q?: string;
    page?: number | null;
    page_size?: number | null;
    license?: Array<MediaLicense> | null;
    license_type?: Array<MediaLicenseType> | null;
    categories?: Array<ImageCategory> | Array<AudioCategory> | null;
    aspect_ratio?: Array<ImageAspectRatio> | null;
    size?: Array<ImageSize> | null;
    length?: Array<AudioLength> | null;
  };
  url: '/media/search';
};

export type SearchMediaMediaSearchGetErrors = {
  /**
   * Validation Error
   */
  422: HttpValidationError;
};

export type SearchMediaMediaSearchGetError =
  SearchMediaMediaSearchGetErrors[keyof SearchMediaMediaSearchGetErrors];

export type SearchMediaMediaSearchGetResponses = {
  /**
   * Successful Response
   */
  200: ImageSearchResponse | AudioSearchResponse;
};

export type SearchMediaMediaSearchGetResponse =
  SearchMediaMediaSearchGetResponses[keyof SearchMediaMediaSearchGetResponses];

export type MediaDetailMediaDetailGetData = {
  body?: never;
  path?: never;
  query: {
    type: MediaType;
    id: string;
  };
  url: '/media/detail';
};

export type MediaDetailMediaDetailGetErrors = {
  /**
   * Validation Error
   */
  422: HttpValidationError;
};

export type MediaDetailMediaDetailGetError =
  MediaDetailMediaDetailGetErrors[keyof MediaDetailMediaDetailGetErrors];

export type MediaDetailMediaDetailGetResponses = {
  /**
   * Successful Response
   */
  200: ImageSearchItem | AudioSearchItem;
};

export type MediaDetailMediaDetailGetResponse =
  MediaDetailMediaDetailGetResponses[keyof MediaDetailMediaDetailGetResponses];

export type DeleteHistoryMediaHistoryDeleteData = {
  body?: never;
  path?: never;
  query?: {
    keyword?: string | null;
  };
  url: '/media/history';
};

export type DeleteHistoryMediaHistoryDeleteErrors = {
  /**
   * Validation Error
   */
  422: HttpValidationError;
};

export type DeleteHistoryMediaHistoryDeleteError =
  DeleteHistoryMediaHistoryDeleteErrors[keyof DeleteHistoryMediaHistoryDeleteErrors];

export type DeleteHistoryMediaHistoryDeleteResponses = {
  /**
   * Successful Response
   */
  200: Array<MediaHistoryResponse>;
};

export type DeleteHistoryMediaHistoryDeleteResponse =
  DeleteHistoryMediaHistoryDeleteResponses[keyof DeleteHistoryMediaHistoryDeleteResponses];

export type GetHistoryMediaHistoryGetData = {
  body?: never;
  path?: never;
  query?: never;
  url: '/media/history';
};

export type GetHistoryMediaHistoryGetResponses = {
  /**
   * Successful Response
   */
  200: Array<MediaHistoryResponse>;
};

export type GetHistoryMediaHistoryGetResponse =
  GetHistoryMediaHistoryGetResponses[keyof GetHistoryMediaHistoryGetResponses];

export type ClientOptions = {
  baseUrl: `${string}://${string}/api/v1` | (string & {});
};
