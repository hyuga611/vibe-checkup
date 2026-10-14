// Guesses from names alone: which tables, columns, collections and buckets hold personal data.

const PERSONAL_TABLE = /^(?:users?|profiles?|accounts?|customers?|members?|clients?|patients?|students?|employees?|contacts?|leads?|orders?|payments?|invoices?|subscriptions?|messages?|chats?|conversations?|bookings?|appointments?|reservations?|addresses|notes?|documents?|applications?|submissions?|responses?|user_\w+|\w+_users?|\w+_profiles?)$/i;
const PERSONAL_COLUMN = /^(?:e?mail|email_address|phone(?:_number)?|tel|mobile|address(?:_line\d?)?|street|postal_code|zip(?:_code)?|birth(?:day|date|_date)?|date_of_birth|dob|password(?:_hash)?|ssn|passport\w*|national_id|iban|card_number|credit_card|salary|income|ip_address|stripe_customer_id|\w*token|\w*secret|api_key|full_name|first_name|last_name)$/i;
const OWNER_COLUMN = /^(?:user_id|owner_id|profile_id|author_id|created_by|customer_id|member_id|uid)$/i;
const SENSITIVE_FILES = /document|invoice|receipt|private|contract|passport|identity|id[-_]?card|kyc|resume|\bcv\b|medical|health|attachment|upload|backup|export|report|statement|tax|payroll|secret/i;
const PUBLIC_FILES = /^(?:avatars?|images?|photos?|pictures?|public|assets|static|logos?|thumbnails?|media|banners?|covers?|icons?|product[-_]?images?|blog[-_]?images?|gallery)$/i;

const snake = (name) => name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();

export const personalName = (name) => PERSONAL_TABLE.test(snake(name));
export const personalColumn = (name) => PERSONAL_COLUMN.test(snake(name));
export const ownerColumn = (name) => OWNER_COLUMN.test(snake(name));
export const sensitiveFiles = (name) => SENSITIVE_FILES.test(name);
export const publicFiles = (name) => PUBLIC_FILES.test(name);
