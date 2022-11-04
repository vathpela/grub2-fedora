/* acpi.c  - Display acpi tables.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2008  Free Software Foundation, Inc.
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
#include <grub/types.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/normal.h>
#include <grub/acpi.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>
#include <grub/dl.h>

#pragma GCC diagnostic ignored "-Wcast-align"

GRUB_MOD_LICENSE ("GPLv3+");

static void
print_strn (grub_uint8_t *str, grub_size_t len)
{
  for (; *str && len; str++, len--)
    grub_printf ("%c", *str);
  for (len++; len; len--)
    grub_printf (" ");
}

#define print_field(x) print_strn(x, sizeof (x))

static void
disp_acpi_table (struct grub_acpi_table_header *t)
{
  print_field (t->signature);
  grub_printf ("%4" PRIuGRUB_UINT32_T "B rev=%u chksum=0x%02x (%s) OEM=", t->length, t->revision, t->checksum,
	       grub_byte_checksum (t, t->length) == 0 ? "valid" : "invalid");
  print_field (t->oemid);
  print_field (t->oemtable);
  grub_printf ("OEMrev=%08" PRIxGRUB_UINT32_T " ", t->oemrev);
  print_field (t->creator_id);
  grub_printf (" %08" PRIxGRUB_UINT32_T "\n", t->creator_rev);
}

struct type_name
{
  grub_uint16_t id;
  const char * const name;
};

static const struct type_name acpi_dbg_serial_subtypes[] = {
  { GRUB_ACPI_DBG_PORT_SERIAL_16550, "16550" },
  { GRUB_ACPI_DBG_PORT_SERIAL_16550_DBG1, "DBGP Revision 1 16650 subset" },
  { GRUB_ACPI_DBG_PORT_SERIAL_MAX311xE, "MAX311xE SPI UART" },
  { GRUB_ACPI_DBG_PORT_SERIAL_PL011, "Arm PL011 UART" },
  { GRUB_ACPI_DBG_PORT_SERIAL_MSM8x60, "MASM8x60" },
  { GRUB_ACPI_DBG_PORT_SERIAL_NVIDIA_16550, "Nvidia 16550" },
  { GRUB_ACPI_DBG_PORT_SERIAL_TI_OMAP, "TI OMAP" },
  { GRUB_ACPI_DBG_PORT_SERIAL_RESERVED_0, "Reserved (Do Not Use)" },
  { GRUB_ACPI_DBG_PORT_SERIAL_APM88xxxx, "APM88xxxx" },
  { GRUB_ACPI_DBG_PORT_SERIAL_MSM8974, "MSM8974" },
  { GRUB_ACPI_DBG_PORT_SERIAL_SAM5250, "SAM5250" },
  { GRUB_ACPI_DBG_PORT_SERIAL_INTEL_USIF, "Intel USIF" },
  { GRUB_ACPI_DBG_PORT_SERIAL_iMX_6, "i.MX 6" },
  { GRUB_ACPI_DBG_PORT_SERIAL_ARM_SBSA_2, "ARM SBSA 2.x Generic UART" },
  { GRUB_ACPI_DBG_PORT_SERIAL_ARM_SBSA, "Arm SBSA Generic UART" },
  { GRUB_ACPI_DBG_PORT_SERIAL_ARM_DCC, "Arm DCC" },
  { GRUB_ACPI_DBG_PORT_SERIAL_BCM2835, "BCM2835" },
  { GRUB_ACPI_DBG_PORT_SERIAL_SDM845_18432, "SDM845 1.8432MHz" },
  { GRUB_ACPI_DBG_PORT_SERIAL_16550_GAS, "16550-compatible + GAS" },
  { GRUB_ACPI_DBG_PORT_SERIAL_SDM845_7372, "SDM845 7.372MHz" },
  { GRUB_ACPI_DBG_PORT_SERIAL_INTEL_LPSS, "Intel LPSS" },
  { GRUB_ACPI_DBG_PORT_INVALID, "" }
};

static const struct type_name acpi_dbg_1394_subtypes[] = {
  { GRUB_ACPI_DBG_PORT_1394_HCI, "IEEE1394 HCI" },
  { GRUB_ACPI_DBG_PORT_INVALID, "" }
};

static const struct type_name acpi_dbg_usb_subtypes[] = {
  { GRUB_ACPI_DBG_PORT_USB_XHCI, "XHCI debug" },
  { GRUB_ACPI_DBG_PORT_USB_EHCI, "EHCI debug" },
  { GRUB_ACPI_DBG_PORT_INVALID, "" }
};

static const struct type_name acpi_gas_asids[] = {
  { GRUB_ACPI_GAS_ASID_SYSTEM_MEMORY, "System Memory space" },
  { GRUB_ACPI_GAS_ASID_SYSTEM_IO, "System I/O space" },
  { GRUB_ACPI_GAS_ASID_EC, "Embedded Controller" },
  { GRUB_ACPI_GAS_ASID_SMBUS, "SMBus" },
  { GRUB_ACPI_GAS_ASID_SYSTEM_CMOS, "SystemCMOS" },
  { GRUB_ACPI_GAS_ASID_PCI_BAR, "PciBarTarget" },
  { GRUB_ACPI_GAS_ASID_IPMI, "IPMI" },
  { GRUB_ACPI_GAS_ASID_GPIO, "General Purpose IO" },
  { GRUB_ACPI_GAS_ASID_GENERIC_SERIAL_BUS, "GenericSerialBus" },
  { GRUB_ACPI_GAS_ASID_PLATFORM_COMMS, "Platform Communications Channel" },
  { GRUB_ACPI_GAS_ASID_FUNCTIONAL_FIXED_HW, "Functional Fixed Hardware" },
  { GRUB_ACPI_DBG_PORT_INVALID, "" }
};

static void
disp_dbg2_generic_entry (struct grub_acpi_dbg2_device_info *di)
{
  unsigned int i;
  grub_uint8_t *addr;
  struct grub_acpi_generic_address_structure *gas;
  grub_uint32_t *addrsz;
  int found = 0;

  addr = (grub_uint8_t *)di + di->namespace_string_offset;
  grub_printf ("namespace:\"");
  for (i = 0; i < di->namespace_string_length; i++)
    grub_printf ("%c", addr[i]);
  grub_printf ("\" ");

  if (di->oem_data_offset && di->oem_data_length)
    {
      addr = (grub_uint8_t *)di + di->oem_data_offset;
      grub_printf ("oem data:");
      for (i = 0; i < di->oem_data_length; i++)
	grub_printf ("%02hhx", addr[i]);
    }
  grub_printf ("\n");

  gas = (struct grub_acpi_generic_address_structure *)
	((grub_uint8_t *)di + di->base_address_register_offset);
  addrsz = (grub_uint32_t *)((grub_uint8_t *)di + di->address_size_offset);

  for (i = 0; i < di->number_of_generic_address_registers; i++, gas++, addrsz++)
    {
      unsigned int j;
      grub_uint32_t segment, bus, device, function, bar;
      grub_uint64_t offset;

      for (j = 0; acpi_gas_asids[j].id != GRUB_ACPI_DBG_PORT_INVALID; j++)
	{
	  if (acpi_gas_asids[j].id == gas->address_space_id)
	    {
	      found = 1;
	      grub_printf ("    asid:%s ", acpi_gas_asids[j].name);
	    }
	}
      if (!found)
	grub_printf ("    asid:0x%02hhx ", gas->address_space_id);

      grub_printf ("width:%d offset:%d access size:", gas->register_bit_width,
		   gas->register_bit_offset);
      switch (gas->access_size)
	{
	case GRUB_ACPI_GAS_ACCESS_SIZE_UNDEFINED:
	  grub_printf ("undefined ");
	  break;
	case GRUB_ACPI_GAS_ACCESS_SIZE_BYTE:
	  grub_printf ("1 (byte) ");
	  break;
	case GRUB_ACPI_GAS_ACCESS_SIZE_WORD:
	  grub_printf ("2 (word) ");
	  break;
	case GRUB_ACPI_GAS_ACCESS_SIZE_DWORD:
	  grub_printf ("4 (Dword) ");
	  break;
	case GRUB_ACPI_GAS_ACCESS_SIZE_QWORD:
	  grub_printf ("8 (Qword) ");
	  break;
	default:
	  grub_printf ("invalid(0x%02hhx) ", gas->access_size);
	  break;
	}

      switch (gas->address_space_id)
	{
	case GRUB_ACPI_GAS_ASID_PCI_CONFIG:
	  /*
	   * Is this right?  Who knows, the spec is completely unreadable.
	   */
	  segment = (gas->address & (0xff00000000000000ull)) >> 56;
	  bus = (gas->address & 0x00ff000000000000ull) >> 48;
	  device = (gas->address & 0x0000ffff00000000ull) >> 32;
	  function = (gas->address & 0x00000000ffff0000ull) >> 16;
	  offset = (gas->address & 0x000000000000ffffull);

	  grub_printf ("pci config %u:%u:%u:%u offset:%"PRIuGRUB_UINT64_T" ",
		       segment, bus, device, function, offset);
	  break;
	case GRUB_ACPI_GAS_ASID_PCI_BAR:
	  segment = (gas->address & (0xff00000000000000ull)) >> 56;
	  bus = (gas->address & 0x00ff000000000000ull) >> 48;
	  device = (gas->address & 0x0000f80000000000ull) >> 43;
	  function = (gas->address & 0x0000070000000000ull) >> 40;
	  bar = (gas->address & 0x000000e000000000ull) >> 37;
	  offset = (gas->address & 0x0000ffffffffffffull);

	  grub_printf ("pci bar %u:%u:%u:%u bar:%u offset:0x%"PRIxGRUB_UINT64_T" ",
		       segment, bus, device, function, bar, offset);
	  break;

	default:
	  grub_printf ("addr:0x%08"PRIxGRUB_UINT64_T" addrsz:%d\n", gas->address,
		       *addrsz);
	  break;
	}
    }
}

static void
disp_dbg2_net_entry (struct grub_acpi_dbg2_device_info *di)
{
  grub_printf ("  network debug port vendor:0x%04hx ", di->port_subtype);
  disp_dbg2_generic_entry (di);
}

static void
disp_dbg2_entry (struct grub_acpi_dbg2_device_info *di,
		 const char *type,
		 const struct type_name *names)
{
  unsigned int i;
  int found = 0;

  for (i = 0; names[i].id != GRUB_ACPI_DBG_PORT_INVALID; i++)
    {
      if (names[i].id == di->port_subtype)
	{
	  grub_printf ("  %s subtype %s ", type, names[i].name);
	  found = 1;
	}
    }

  if (!found)
    grub_printf ("  %s subtype 0x%04hx ", type, di->port_subtype);

  disp_dbg2_generic_entry (di);
}

static void
disp_dbg2_table (struct grub_acpi_dbg2 *t)
{
  struct grub_acpi_dbg2_device_info *di;
  grub_uint32_t n, i;
  grub_uint8_t *addr = (grub_uint8_t *)t;

  disp_acpi_table (&t->hdr);
  /*
   * The spec says the version should be 0, but in practice firmware seems to
   * always set it to 1.
   */
  if (t->hdr.revision != 0)
      grub_printf ("unexpected DBG2 version number %d\n", t->hdr.revision);

  n = t->number_dbg_device_info;
  addr += t->offset_dbg_device_info;

  di = (struct grub_acpi_dbg2_device_info *)addr;
  for (i = 0; i < n; i++, addr += di->length)
  {
    di = (struct grub_acpi_dbg2_device_info *)addr;

    switch (di->port_type)
      {
      case GRUB_ACPI_DBG_PORT_SERIAL:
	disp_dbg2_entry (di, "Serial Port", acpi_dbg_serial_subtypes);
	break;
      case GRUB_ACPI_DBG_PORT_1394:
	disp_dbg2_entry (di, "IEEE1394", acpi_dbg_1394_subtypes);
	break;
      case GRUB_ACPI_DBG_PORT_USB:
	disp_dbg2_entry (di, "USB", acpi_dbg_usb_subtypes);
	break;
      case GRUB_ACPI_DBG_PORT_NET:
	disp_dbg2_net_entry(di);
	break;
      default:
	grub_printf ("  debug port type 0x%04hx\n", di->port_type);
	disp_dbg2_generic_entry (di);
	break;
      }
  }
}

static void
disp_madt_table (struct grub_acpi_madt *t)
{
  struct grub_acpi_madt_entry_header *d;
  grub_uint32_t len;

  disp_acpi_table (&t->hdr);
  grub_printf ("Local APIC=%08" PRIxGRUB_UINT32_T "  Flags=%08"
	       PRIxGRUB_UINT32_T "\n",
	       t->lapic_addr, t->flags);
  len = t->hdr.length - sizeof (struct grub_acpi_madt);
  d = t->entries;
  for (;len > 0; len -= d->len, d = (void *) ((grub_uint8_t *) d + d->len))
    {
      switch (d->type)
	{
	case GRUB_ACPI_MADT_ENTRY_TYPE_LAPIC:
	  {
	    struct grub_acpi_madt_entry_lapic *dt = (void *) d;
	    grub_printf ("  LAPIC ACPI_ID=%02x APIC_ID=%02x Flags=%08x\n",
			 dt->acpiid, dt->apicid, dt->flags);
	    if (dt->hdr.len != sizeof (*dt))
	      grub_printf ("   table size mismatch %d != %d\n", dt->hdr.len,
			   (int) sizeof (*dt));
	    break;
	  }

	case GRUB_ACPI_MADT_ENTRY_TYPE_IOAPIC:
	  {
	    struct grub_acpi_madt_entry_ioapic *dt = (void *) d;
	    grub_printf ("  IOAPIC ID=%02x address=%08x GSI=%08x\n",
			 dt->id, dt->address, dt->global_sys_interrupt);
	    if (dt->hdr.len != sizeof (*dt))
	      grub_printf ("   table size mismatch %d != %d\n", dt->hdr.len,
			   (int) sizeof (*dt));
	    if (dt->pad)
	      grub_printf ("   non-zero pad: %02x\n", dt->pad);
	    break;
	  }

	case GRUB_ACPI_MADT_ENTRY_TYPE_INTERRUPT_OVERRIDE:
	  {
	    struct grub_acpi_madt_entry_interrupt_override *dt = (void *) d;
	    grub_printf ("  Int Override bus=%x src=%x GSI=%08x Flags=%04x\n",
			 dt->bus, dt->source, dt->global_sys_interrupt,
			 dt->flags);
	    if (dt->hdr.len != sizeof (*dt))
	      grub_printf ("   table size mismatch %d != %d\n", dt->hdr.len,
			   (int) sizeof (*dt));
	  }
	  break;

	case GRUB_ACPI_MADT_ENTRY_TYPE_LAPIC_NMI:
	  {
	    struct grub_acpi_madt_entry_lapic_nmi *dt = (void *) d;
	    grub_printf ("  LAPIC_NMI ACPI_ID=%02x Flags=%04x lint=%02x\n",
			 dt->acpiid, dt->flags, dt->lint);
	    if (dt->hdr.len != sizeof (*dt))
	      grub_printf ("   table size mismatch %d != %d\n", dt->hdr.len,
			   (int) sizeof (*dt));
	    break;
	  }

	case GRUB_ACPI_MADT_ENTRY_TYPE_SAPIC:
	  {
	    struct grub_acpi_madt_entry_sapic *dt = (void *) d;
	    grub_printf ("  IOSAPIC Id=%02x GSI=%08x Addr=%016" PRIxGRUB_UINT64_T
			 "\n",
			 dt->id, dt->global_sys_interrupt_base,
			 dt->addr);
	    if (dt->hdr.len != sizeof (*dt))
	      grub_printf ("   table size mismatch %d != %d\n", dt->hdr.len,
			   (int) sizeof (*dt));
	    if (dt->pad)
	      grub_printf ("   non-zero pad: %02x\n", dt->pad);

	  }
	  break;
	case GRUB_ACPI_MADT_ENTRY_TYPE_LSAPIC:
	  {
	    struct grub_acpi_madt_entry_lsapic *dt = (void *) d;
	    grub_printf ("  LSAPIC ProcId=%02x ID=%02x EID=%02x Flags=%x",
			 dt->cpu_id, dt->id, dt->eid, dt->flags);
	    if (dt->flags & GRUB_ACPI_MADT_ENTRY_SAPIC_FLAGS_ENABLED)
	      grub_printf (" Enabled\n");
	    else
	      grub_printf (" Disabled\n");
	    if (d->len > sizeof (struct grub_acpi_madt_entry_sapic))
	      grub_printf ("  UID val=%08x, Str=%s\n", dt->cpu_uid,
			   dt->cpu_uid_str);
	    if (dt->hdr.len != sizeof (*dt) + grub_strlen ((char *) dt->cpu_uid_str) + 1)
	      grub_printf ("   table size mismatch %d != %d\n", dt->hdr.len,
			   (int) sizeof (*dt));
	    if (dt->pad[0] || dt->pad[1] || dt->pad[2])
	      grub_printf ("   non-zero pad: %02x%02x%02x\n", dt->pad[0], dt->pad[1], dt->pad[2]);
	  }
	  break;
	case GRUB_ACPI_MADT_ENTRY_TYPE_PLATFORM_INT_SOURCE:
	  {
	    struct grub_acpi_madt_entry_platform_int_source *dt = (void *) d;
	    static const char * const platint_type[] =
	      {"Nul", "PMI", "INIT", "CPEI"};

	    grub_printf ("  Platform INT flags=%04x type=%02x (%s)"
			 " ID=%02x EID=%02x\n",
			 dt->flags, dt->inttype,
			 (dt->inttype < ARRAY_SIZE (platint_type))
			 ? platint_type[dt->inttype] : "??", dt->cpu_id,
			 dt->cpu_eid);
	    grub_printf ("  IOSAPIC Vec=%02x GSI=%08x source flags=%08x\n",
			 dt->sapic_vector, dt->global_sys_int, dt->src_flags);
	  }
	  break;
	default:
	  grub_printf ("  type=%x l=%u ", d->type, d->len);
	  grub_printf (" ??\n");
	}
    }
}

static void
disp_acpi_xsdt_table (struct grub_acpi_table_header *t)
{
  grub_uint32_t len;
  grub_uint64_t *desc;

  disp_acpi_table (t);
  len = t->length - sizeof (*t);
  desc = (grub_uint64_t *) (t + 1);
  for (; len >= sizeof (*desc); desc++, len -= sizeof (*desc))
    {
#if GRUB_CPU_SIZEOF_VOID_P == 4
      if (*desc >= (1ULL << 32))
	{
	  grub_printf ("Unreachable table\n");
	  continue;
	}
#endif
      t = (struct grub_acpi_table_header *) (grub_addr_t) *desc;

      if (t == NULL)
	continue;

      if (grub_memcmp (t->signature, GRUB_ACPI_MADT_SIGNATURE,
		       sizeof (t->signature)) == 0)
	disp_madt_table ((struct grub_acpi_madt *) t);
      else if (grub_memcmp (t->signature, GRUB_ACPI_DBG2_SIGNATURE,
			    sizeof (t->signature)) == 0)
	disp_dbg2_table ((struct grub_acpi_dbg2 *) t);
      else
	disp_acpi_table (t);
    }
}

static void
disp_acpi_rsdt_table (struct grub_acpi_table_header *t)
{
  grub_uint32_t len;
  grub_uint32_t *desc;

  disp_acpi_table (t);
  len = t->length - sizeof (*t);
  desc = (grub_uint32_t *) (t + 1);
  for (; len >= sizeof (*desc); desc++, len -= sizeof (*desc))
    {
      t = (struct grub_acpi_table_header *) (grub_addr_t) *desc;

      if (t == NULL)
	continue;

      if (grub_memcmp (t->signature, GRUB_ACPI_MADT_SIGNATURE,
		       sizeof (t->signature)) == 0)
	disp_madt_table ((struct grub_acpi_madt *) t);
      else
	disp_acpi_table (t);
    }
}

static void
disp_acpi_rsdpv1 (struct grub_acpi_rsdp_v10 *rsdp)
{
  print_field (rsdp->signature);
  grub_printf ("chksum:%02x (%s), OEM-ID: ", rsdp->checksum, grub_byte_checksum (rsdp, sizeof (*rsdp)) == 0 ? "valid" : "invalid");
  print_field (rsdp->oemid);
  grub_printf ("rev=%d\n", rsdp->revision);
  grub_printf ("RSDT=%08" PRIxGRUB_UINT32_T "\n", rsdp->rsdt_addr);
}

static void
disp_acpi_rsdpv2 (struct grub_acpi_rsdp_v20 *rsdp)
{
  disp_acpi_rsdpv1 (&rsdp->rsdpv1);
  grub_printf ("len=%d chksum=%02x (%s) XSDT=%016" PRIxGRUB_UINT64_T "\n", rsdp->length, rsdp->checksum, grub_byte_checksum (rsdp, rsdp->length) == 0 ? "valid" : "invalid",
	       rsdp->xsdt_addr);
  if (rsdp->length != sizeof (*rsdp))
    grub_printf (" length mismatch %d != %d\n", rsdp->length,
		 (int) sizeof (*rsdp));
  if (rsdp->reserved[0] || rsdp->reserved[1] || rsdp->reserved[2])
    grub_printf (" non-zero reserved %02x%02x%02x\n", rsdp->reserved[0], rsdp->reserved[1], rsdp->reserved[2]);
}

static const struct grub_arg_option options[] = {
  {"v1", '1', 0, N_("Show version 1 tables only."), 0, ARG_TYPE_NONE},
  {"v2", '2', 0, N_("Show version 2 and version 3 tables only."), 0, ARG_TYPE_NONE},
  {0, 0, 0, 0, 0, 0}
};

static grub_err_t
grub_cmd_lsacpi (struct grub_extcmd_context *ctxt,
		 int argc __attribute__ ((unused)),
		 char **args __attribute__ ((unused)))
{
  if (!ctxt->state[1].set)
    {
      struct grub_acpi_rsdp_v10 *rsdp1 = grub_acpi_get_rsdpv1 ();
      if (!rsdp1)
	grub_printf ("No RSDPv1\n");
      else
	{
	  grub_printf ("RSDPv1 signature:");
	  disp_acpi_rsdpv1 (rsdp1);
	  disp_acpi_rsdt_table ((void *) (grub_addr_t) rsdp1->rsdt_addr);
	}
    }

  if (!ctxt->state[0].set)
    {
      struct grub_acpi_rsdp_v20 *rsdp2 = grub_acpi_get_rsdpv2 ();
      if (!rsdp2)
	grub_printf ("No RSDPv2\n");
      else
	{
#if GRUB_CPU_SIZEOF_VOID_P == 4
	  if (rsdp2->xsdt_addr >= (1ULL << 32))
	    grub_printf ("Unreachable RSDPv2\n");
	  else
#endif
	    {
	      grub_printf ("RSDPv2 signature:");
	      disp_acpi_rsdpv2 (rsdp2);
	      disp_acpi_xsdt_table ((void *) (grub_addr_t) rsdp2->xsdt_addr);
	      grub_printf ("\n");
	    }
	}
    }
  return GRUB_ERR_NONE;
}

static grub_extcmd_t cmd;

GRUB_MOD_INIT(lsapi)
{
  cmd = grub_register_extcmd ("lsacpi", grub_cmd_lsacpi, 0, "[-1|-2]",
			      N_("Show ACPI information."), options);
}

GRUB_MOD_FINI(lsacpi)
{
  grub_unregister_extcmd (cmd);
}


