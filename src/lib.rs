use exe::{pe::PtrPE, CCharString, PE};
use windows_sys::{
	core::PCSTR,
	s,
	Win32::{
		Foundation::{FALSE, HMODULE},
		System::LibraryLoader::GetModuleHandleA,
		System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
		System::SystemServices::DLL_PROCESS_ATTACH,
		UI::WindowsAndMessaging::{MessageBoxA, MB_OK},
	},
};

struct Patch {
	pattern: Vec<u8>,
	diff_offset: usize,
	patch: Vec<u8>,
}

fn get_executable_range() -> Result<(usize, usize), exe::Error> {
	let pe_address = unsafe { GetModuleHandleA(std::ptr::null()) };
	let ptr_pe = unsafe { PtrPE::from_memory(pe_address as *const u8)? };
	let section_table = ptr_pe.get_section_table()?;

	for section in section_table {
		if let Ok(section_name) = section.name.as_str() {
			if section_name == ".text" {
				return Ok((section.virtual_address.0 as usize + pe_address as usize, section.virtual_size as usize));
			}
		}
	}

	Err(exe::Error::SectionNotFound)
}

fn apply_patch(patch: &Patch, base_addr: usize, size: usize) -> Result<(), ()> {
	let slice_pattern = &patch.pattern[..];

	for addr in base_addr..=((base_addr + size) - patch.pattern.len()) {
		let slice_binary = unsafe { std::slice::from_raw_parts(addr as *const u8, patch.pattern.len()) };

		if slice_binary == slice_pattern {
			let mut protection_flags: PAGE_PROTECTION_FLAGS = 0;
			unsafe {
				if VirtualProtect(
					(addr + patch.diff_offset) as *const std::ffi::c_void,
					patch.patch.len(),
					PAGE_EXECUTE_READWRITE,
					&mut protection_flags as *mut PAGE_PROTECTION_FLAGS,
				) == FALSE
				{
					return Err(());
				}

				let slice_to_patch = std::slice::from_raw_parts_mut(addr as *mut u8, patch.patch.len());
				let slice_patch = &patch.patch[..];
				slice_to_patch.clone_from_slice(slice_patch);

				if VirtualProtect(
					(addr + patch.diff_offset) as *const std::ffi::c_void,
					patch.patch.len(),
					protection_flags,
					&mut protection_flags as *mut PAGE_PROTECTION_FLAGS,
				) == FALSE
				{
					return Err(());
				}
			}
			return Ok(());
		}
	}

	Err(())
}

fn patch_executable() {
	let scaling_patch = Patch {
		pattern: vec![0xF3, 0x0F, 0x10, 0x00, 0x0F, 0x2F, 0xC2, 0x76, 0x04, 0x8D, 0x44, 0x24, 0x04, 0xF3, 0x0F, 0x10, 0x00],
		diff_offset: 7,
		patch: vec![0xEB],
	};

	match get_executable_range() {
		Ok((base_addr, size)) => {
			if apply_patch(&scaling_patch, base_addr, size).is_err() {
				error_message(s!("Failed to apply the UI scaling patch!"));
			}
		}
		Err(_) => error_message(s!("Failed to get executable range!")),
	}
}

fn error_message(error_message: PCSTR) {
	unsafe {
		MessageBoxA(0, error_message, s!("Error"), MB_OK);
	}
}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HMODULE, call_reason: u32, _: *mut ()) -> bool {
	match call_reason {
		DLL_PROCESS_ATTACH => patch_executable(),
		_ => (),
	}

	true
}
