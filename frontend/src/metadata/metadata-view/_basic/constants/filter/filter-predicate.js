import { gettext } from '../../../../../utils/constants';

const FILTER_PREDICATE_TYPE = {
  CONTAINS: 'contains',
  NOT_CONTAIN: 'does_not_contain',
  IS: 'is',
  IS_NOT: 'is_not',
  EQUAL: 'equal',
  NOT_EQUAL: 'not_equal',
  LESS: 'less',
  GREATER: 'greater',
  LESS_OR_EQUAL: 'less_or_equal',
  GREATER_OR_EQUAL: 'greater_or_equal',
  EMPTY: 'is_empty',
  NOT_EMPTY: 'is_not_empty',
  IS_WITHIN: 'is_within',
  IS_BEFORE: 'is_before',
  IS_AFTER: 'is_after',
  IS_ON_OR_BEFORE: 'is_on_or_before',
  IS_ON_OR_AFTER: 'is_on_or_after',
  HAS_ANY_OF: 'has_any_of',
  HAS_ALL_OF: 'has_all_of',
  HAS_NONE_OF: 'has_none_of',
  IS_EXACTLY: 'is_exactly',
  INCLUDE_ME: 'include_me',
  IS_CURRENT_USER_ID: 'is_current_user_ID',
  IS_ANY_OF: 'is_any_of',
  IS_NONE_OF: 'is_none_of',
};

const FILTER_PREDICATE_SHOW = {
  [FILTER_PREDICATE_TYPE.CONTAINS]: gettext('contains'),
  [FILTER_PREDICATE_TYPE.NOT_CONTAIN]: gettext('does not contain'),
  [FILTER_PREDICATE_TYPE.IS]: gettext('is'),
  [FILTER_PREDICATE_TYPE.IS_NOT]: gettext('is not'),
  [FILTER_PREDICATE_TYPE.EQUAL]: '\u003d',
  [FILTER_PREDICATE_TYPE.NOT_EQUAL]: '\u2260',
  [FILTER_PREDICATE_TYPE.LESS]: '\u003C',
  [FILTER_PREDICATE_TYPE.GREATER]: '\u003E',
  [FILTER_PREDICATE_TYPE.LESS_OR_EQUAL]: '\u2264',
  [FILTER_PREDICATE_TYPE.GREATER_OR_EQUAL]: '\u2265',
  [FILTER_PREDICATE_TYPE.EMPTY]: gettext('is empty'),
  [FILTER_PREDICATE_TYPE.NOT_EMPTY]: gettext('is not empty'),
  [FILTER_PREDICATE_TYPE.IS_WITHIN]: gettext('is within...'),
  [FILTER_PREDICATE_TYPE.IS_BEFORE]: gettext('is before...'),
  [FILTER_PREDICATE_TYPE.IS_AFTER]: gettext('is after...'),
  [FILTER_PREDICATE_TYPE.IS_ON_OR_BEFORE]: gettext('is on or before...'),
  [FILTER_PREDICATE_TYPE.IS_ON_OR_AFTER]: gettext('is on or after...'),
  [FILTER_PREDICATE_TYPE.HAS_ANY_OF]: gettext('has any of...'),
  [FILTER_PREDICATE_TYPE.HAS_ALL_OF]: gettext('has all of...'),
  [FILTER_PREDICATE_TYPE.HAS_NONE_OF]: gettext('has none of...'),
  [FILTER_PREDICATE_TYPE.IS_EXACTLY]: gettext('is exactly...'),
  [FILTER_PREDICATE_TYPE.IS_CURRENT_USER_ID]: gettext('is current user\'s ID'),
  [FILTER_PREDICATE_TYPE.INCLUDE_ME]: gettext('include the current user')
};

export {
  FILTER_PREDICATE_TYPE,
  FILTER_PREDICATE_SHOW,
};
