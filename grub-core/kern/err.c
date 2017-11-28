/* err.c - error handling routines */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2005,2007,2008  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/err.h>
#include <grub/misc.h>
#include <stdarg.h>
#include <grub/i18n.h>

#define GRUB_ERROR_STACK_SIZE	10

grub_err_t grub_errno;
char grub_errmsg[GRUB_MAX_ERRMSG];
int grub_err_printed_errors;

static struct grub_error_saved grub_error_stack_items[GRUB_ERROR_STACK_SIZE];

static int grub_error_stack_pos;
static int grub_error_stack_assert;

static const char * const err_strings[] =
{
    [GRUB_ERR_NONE] = "GRUB_ERR_NONE",
    [GRUB_ERR_TEST_FAILURE] = "GRUB_ERR_TEST_FAILURE",
    [GRUB_ERR_BAD_MODULE] = "GRUB_ERR_BAD_MODULE",
    [GRUB_ERR_OUT_OF_MEMORY] = "GRUB_ERR_OUT_OF_MEMORY",
    [GRUB_ERR_BAD_FILE_TYPE] = "GRUB_ERR_BAD_FILE_TYPE",
    [GRUB_ERR_FILE_NOT_FOUND] = "GRUB_ERR_FILE_NOT_FOUND",
    [GRUB_ERR_FILE_READ_ERROR] = "GRUB_ERR_FILE_READ_ERROR",
    [GRUB_ERR_BAD_FILENAME] = "GRUB_ERR_BAD_FILENAME",
    [GRUB_ERR_UNKNOWN_FS] = "GRUB_ERR_UNKNOWN_FS",
    [GRUB_ERR_BAD_FS] = "GRUB_ERR_BAD_FS",
    [GRUB_ERR_BAD_NUMBER] = "GRUB_ERR_BAD_NUMBER",
    [GRUB_ERR_OUT_OF_RANGE] = "GRUB_ERR_OUT_OF_RANGE",
    [GRUB_ERR_UNKNOWN_DEVICE] = "GRUB_ERR_UNKNOWN_DEVICE",
    [GRUB_ERR_BAD_DEVICE] = "GRUB_ERR_BAD_DEVICE",
    [GRUB_ERR_READ_ERROR] = "GRUB_ERR_READ_ERROR",
    [GRUB_ERR_WRITE_ERROR] = "GRUB_ERR_WRITE_ERROR",
    [GRUB_ERR_UNKNOWN_COMMAND] = "GRUB_ERR_UNKNOWN_COMMAND",
    [GRUB_ERR_INVALID_COMMAND] = "GRUB_ERR_INVALID_COMMAND",
    [GRUB_ERR_BAD_ARGUMENT] = "GRUB_ERR_BAD_ARGUMENT",
    [GRUB_ERR_BAD_PART_TABLE] = "GRUB_ERR_BAD_PART_TABLE",
    [GRUB_ERR_UNKNOWN_OS] = "GRUB_ERR_UNKNOWN_OS",
    [GRUB_ERR_BAD_OS] = "GRUB_ERR_BAD_OS",
    [GRUB_ERR_NO_KERNEL] = "GRUB_ERR_NO_KERNEL",
    [GRUB_ERR_BAD_FONT] = "GRUB_ERR_BAD_FONT",
    [GRUB_ERR_NOT_IMPLEMENTED_YET] = "GRUB_ERR_NOT_IMPLEMENTED_YET",
    [GRUB_ERR_SYMLINK_LOOP] = "GRUB_ERR_SYMLINK_LOOP",
    [GRUB_ERR_BAD_COMPRESSED_DATA] = "GRUB_ERR_BAD_COMPRESSED_DATA",
    [GRUB_ERR_MENU] = "GRUB_ERR_MENU",
    [GRUB_ERR_TIMEOUT] = "GRUB_ERR_TIMEOUT",
    [GRUB_ERR_IO] = "GRUB_ERR_IO",
    [GRUB_ERR_ACCESS_DENIED] = "GRUB_ERR_ACCESS_DENIED",
    [GRUB_ERR_EXTRACTOR] = "GRUB_ERR_EXTRACTOR",
    [GRUB_ERR_NET_BAD_ADDRESS] = "GRUB_ERR_NET_BAD_ADDRESS",
    [GRUB_ERR_NET_ROUTE_LOOP] = "GRUB_ERR_NET_ROUTE_LOOP",
    [GRUB_ERR_NET_NO_ROUTE] = "GRUB_ERR_NET_NO_ROUTE",
    [GRUB_ERR_NET_NO_ANSWER] = "GRUB_ERR_NET_NO_ANSWER",
    [GRUB_ERR_NET_NO_CARD] = "GRUB_ERR_NET_NO_CARD",
    [GRUB_ERR_WAIT] = "GRUB_ERR_WAIT",
    [GRUB_ERR_BUG] = "GRUB_ERR_BUG",
    [GRUB_ERR_NET_PORT_CLOSED] = "GRUB_ERR_NET_PORT_CLOSED",
    [GRUB_ERR_NET_INVALID_RESPONSE] = "GRUB_ERR_NET_INVALID_RESPONSE",
    [GRUB_ERR_NET_UNKNOWN_ERROR] = "GRUB_ERR_NET_UNKNOWN_ERROR",
    [GRUB_ERR_NET_PACKET_TOO_BIG] = "GRUB_ERR_NET_PACKET_TOO_BIG",
    [GRUB_ERR_NET_NO_DOMAIN] = "GRUB_ERR_NET_NO_DOMAIN",
    [GRUB_ERR_EOF] = "GRUB_ERR_EOF",
    [GRUB_ERR_BAD_SIGNATURE] = "GRUB_ERR_BAD_SIGNATURE",

    [GRUB_ERR_MAX] = "(Invalid error number)" /* Make sure this stays last */
};

const char *
grub_strerror (grub_err_t n)
{
  if (n < 0 || n >= GRUB_ERR_MAX)
    n = GRUB_ERR_MAX;
  return err_strings[n];
}

grub_err_t
grub_error (grub_err_t n, const char *fmt, ...)
{
  va_list ap;

  grub_errno = n;

  va_start (ap, fmt);
  grub_vsnprintf (grub_errmsg, sizeof (grub_errmsg), _(fmt), ap);
  va_end (ap);

  return n;
}

void
grub_error_push (void)
{
  /* Only add items to stack, if there is enough room.  */
  if (grub_error_stack_pos < GRUB_ERROR_STACK_SIZE)
    {
      /* Copy active error message to stack.  */
      grub_error_stack_items[grub_error_stack_pos].grub_errno = grub_errno;
      grub_memcpy (grub_error_stack_items[grub_error_stack_pos].errmsg,
                   grub_errmsg,
                   sizeof (grub_errmsg));

      /* Advance to next error stack position.  */
      grub_error_stack_pos++;
    }
  else
    {
      /* There is no room for new error message. Discard new error message
         and mark error stack assertion flag.  */
      grub_error_stack_assert = 1;
    }

  /* Allow further operation of other components by resetting
     active errno to GRUB_ERR_NONE.  */
  grub_errno = GRUB_ERR_NONE;
}

int
grub_error_pop (void)
{
  if (grub_error_stack_pos > 0)
    {
      /* Pop error message from error stack to current active error.  */
      grub_error_stack_pos--;

      grub_errno = grub_error_stack_items[grub_error_stack_pos].grub_errno;
      grub_memcpy (grub_errmsg,
                   grub_error_stack_items[grub_error_stack_pos].errmsg,
                   sizeof (grub_errmsg));

      return 1;
    }
  else
    {
      /* There is no more items on error stack, reset to no error state.  */
      grub_errno = GRUB_ERR_NONE;

      return 0;
    }
}

grub_err_t
grub_error_peek (void)
{
  if (grub_error_stack_pos > 0)
    return grub_error_stack_items[grub_error_stack_pos-1].grub_errno;
  return GRUB_ERR_NONE;
}

void
grub_print_error (void)
{
  /* Print error messages in reverse order. First print active error message
     and then empty error stack.  */
  do
    {
      if (grub_errno != GRUB_ERR_NONE)
	{
	  grub_err_printf (_("error: %s.\n"), grub_errmsg);
	  grub_err_printed_errors++;
	}
    }
  while (grub_error_pop ());

  /* If there was an assert while using error stack, report about it.  */
  if (grub_error_stack_assert)
    {
      grub_err_printf ("assert: error stack overflow detected!\n");
      grub_error_stack_assert = 0;
    }
}
