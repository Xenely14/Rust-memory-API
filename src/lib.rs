#![allow(dead_code)]

const PATH_SIZE: usize = 512;
const MODULE_NAME_SIZE: usize = 256;

const PROCESS_ALL_ACCESS: u32 = 0x001F0FFF;

pub const MEM_DECOMMIT: u32 = 0x00004000;
pub const MEM_RELEASE: u32 = 0x00008000;
pub const MEM_COALESCE_PLACEHOLDERS: u32 = 0x00000001;
pub const MEM_PRESERVE_PLACEHOLDER: u32 = 0x00000002;

pub const MEM_COMMIT: u32 = 0x00001000;
pub const MEM_RESERVE: u32 = 0x00002000;
pub const MEM_RESET: u32 = 0x00080000;
pub const MEM_RESET_UNDO: u32 = 0x1000000;
pub const MEM_LARGE_PAGES: u32 = 0x20000000;
pub const MEM_PHYSICAL: u32 = 0x00400000;
pub const MEM_TOP_DOWN: u32 = 0x00100000;

pub const PAGE_NOACCESS: u32 = 0x001;
pub const PAGE_READONLY: u32 = 0x002;
pub const PAGE_READWRITE: u32 = 0x004;
pub const PAGE_WRITECOPY: u32 = 0x008;
pub const PAGE_EXECUTE_READ: u32 = 0x0020;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x0040;

pub const LIST_MODULES_32BIT: u32 = 0x01;
pub const LIST_MODULES_64BIT: u32 = 0x02;
pub const LIST_MODULES_ALL: u32 = 0x03;
pub const LIST_MODULES_DEFAULT: u32 = 0x0;

#[allow(improper_ctypes)]
#[link(name="kernel32")]
extern "system"
{
    fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> *const ();
    fn ReadProcessMemory(process_handle: *const (), read_address: *const (), buffer: *const (), buffer_size: usize, bytes_read: *const usize) -> i32;
    fn WriteProcessMemory(process_handle: *const (), write_address: *const (), buffer: *const (), buffer_size: usize, bytes_written : *const usize) -> i32;
    fn VirtualAllocEx(process_handle: *const (), desired_location: *const (), allocation_size: usize, allocation_type: u32, protection: u32) -> *const ();
    fn VirtualFreeEx(process_handle: *const (), allocation_address: *const (), allocation_size: usize, free_type: u32) -> i32;
    fn IsWow64Process(process_handle: *const (), is_64_bit: *const i32) -> i32;
    fn VirtualQueryEx(process_handle: *const (), address: *const (), memory_info: *const MemoryInformation, bytes_length: usize) -> usize;
}

#[allow(improper_ctypes)]
#[link(name="psapi")]
extern "system"
{
    fn EnumProcesses(process_ids_list: *const u32, process_ids_list_size: u32, bytes_returned: *const u32) -> i32;
    fn EnumProcessModulesEx(process_handle: *const (), modules_list: *const *const (), module_list_size: u32, bytes_returned: *const u32, filter: u32) -> i32;
    fn GetProcessImageFileNameW(process_handle: *const (), name_buffer: *const u16, buffer_size: u32) -> u32;
    fn GetModuleInformation(process_handle: *const (), module: *const (), module_info: *const Module, bytes_returned: u32) -> i32;
    fn GetModuleBaseNameW(process_handle: *const (), module: *const (), name_buffer: *const u16, buffer_size: u32) -> u32;
}

/// ## EN
/// Structure of process module.<br/>
/// Contains module base address, size of image, entry point and name.
/// ## RU
/// Структура модуля процесса.<br/>
/// Содержит базовый адрес, размер изображения, точку входа и имя модуля.
#[repr(C)]
#[derive(Debug)]
pub struct Module
{
    pub base_address: *const (),
    pub size_of_image: u32,
    pub entry_point: *const (),

    // Local attributes
    pub name: String
}

/// ## EN
/// Structure of process memory information.<br/>
/// Contains information about memory page in process.
/// ## RU
/// Структура информации памяти процесса.<br/>
/// Содержит информацию о участке памяти в процессе.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryInformation
{
    pub base_address: u64,
    pub allocation_base: u64,
    pub allocation_protection: u32,
    pub alignment_1: u32,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    pub memory_type: u32,
    pub alignment_2: u32
}

/// ## EN
/// Structure of process allowing to interact with virtual memory.<br/>
/// Contains process name, handle and ID (PID).
/// #### Example:
/// ```
/// let name_process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
/// let id_process: Process = Process::new_from_id(12604).unwrap();
///
/// // Process { handle: 0x3f0, name: "cheatengine-x86_64.exe", id: 12604 }
/// // Process { handle: 0x3f0, name: "cheatengine-x86_64.exe", id: 12604 }
/// println!("{:?}", name_process);
/// println!("{:?}", id_process);
/// ```
/// ## RU
/// Структура процесса, позволяющая взаимодейстовать с виртуальной памятью.<br/>
/// Содержит дескриптор, имя и ID (PID) процесса.
/// #### Пример:
/// ```
/// let name_process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
/// let id_process: Process = Process::new_from_id(12604).unwrap();
///
/// // Process { handle: 0x3f0, name: "cheatengine-x86_64.exe", id: 12604 }
/// // Process { handle: 0x3f0, name: "cheatengine-x86_64.exe", id: 12604 }
/// println!("{:?}", name_process);
/// println!("{:?}", id_process);
/// ```
#[repr(C)]
#[derive(Debug)]
pub struct Process
{
    pub handle: *const (),
    pub name: String,
    pub id: u32
}

impl Process
{

    /// ## EN
    /// Constructs process object from process ID.<br/>
    /// Returns [`Option`] containing `Process` object if operation successed, otherwise returns [`None`].
    /// #### Example:
    /// ```
    /// #[derive(Debug)]
    /// struct RandomThreeInts
    /// {
    ///     x: i32,
    ///     y: i32,
    ///     z: i32
    /// }
    ///
    /// let process: Process = Process::new_from_id(24456).unwrap();
    /// let random_struct: RandomThreeInts = process.read_memory::<RandomThreeInts>(0x00BE8D60).unwrap();
    /// 
    /// // process -> Process { handle: 0x458, name: "cheatengine-x86_64.exe", id: 24456 }
    /// // read struct -> RandomThreeInts { x: 255, y: 0, z: 16987320 }
    /// println!("process -> {process:?}");
    /// println!("read struct -> {random_struct:?}");
    /// ```
    /// ## RU
    /// Создает объект процесса из ID процесса.<br/>
    /// Возвращает [`Option`], содержащий объект `Process` в cлучае успешной операции, в противном случае возвращает [`None`]
    /// #### Пример:
    /// ```
    /// #[derive(Debug)]
    /// struct RandomThreeInts
    /// {
    ///     x: i32,
    ///     y: i32,
    ///     z: i32
    /// }
    ///
    /// let process: Process = Process::new_from_id(24456).unwrap();
    /// let random_struct: RandomThreeInts = process.read_memory::<RandomThreeInts>(0x00BE8D60).unwrap();
    /// 
    /// // process -> Process { handle: 0x458, name: "cheatengine-x86_64.exe", id: 24456 }
    /// // read struct -> RandomThreeInts { x: 255, y: 0, z: 16987320 }
    /// println!("process -> {process:?}");
    /// println!("read struct -> {random_struct:?}");
    /// ```
    pub fn new_from_id(process_id: u32) -> Option<Self>
    {
        match list_processes()
        {
            None => None,
            Some(processes) =>
            {
                for (id, name) in processes
                {
                    if process_id == id {return Some(Self{handle: unsafe{OpenProcess(PROCESS_ALL_ACCESS, 0, id)}, name, id})}
                }
                None
            }
        }
    }

    /// ## EN
    /// Constructs process object from process name.<br/>
    /// Returns [`Option`] containing `Process` object if operation successed, otherwise returns [`None`].
    /// #### Example:
    /// ```
    /// #[derive(Debug)]
    /// struct RandomThreeInts
    /// {
    ///     x: i32,
    ///     y: i32,
    ///     z: i32
    /// }
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// let random_struct: RandomThreeInts = process.read_memory::<RandomThreeInts>(0x00BE8D60).unwrap();
    /// 
    /// // process -> Process { handle: 0x458, name: "cheatengine-x86_64.exe", id: 24456 }
    /// // read struct -> RandomThreeInts { x: 255, y: 0, z: 16987320 }
    /// println!("process -> {process:?}");
    /// println!("read struct -> {random_struct:?}");
    /// ```
    /// ## RU
    /// Создает объект процесса из имени процесса.<br/>
    /// Возвращает [`Option`], содержащий объект `Process` в cлучае успешной операции, в противном случае возвращает [`None`]
    /// #### Пример:
    /// ```
    /// #[derive(Debug)]
    /// struct RandomThreeInts
    /// {
    ///     x: i32,
    ///     y: i32,
    ///     z: i32
    /// }
    ///
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// let random_struct: RandomThreeInts = process.read_memory::<RandomThreeInts>(0x00BE8D60).unwrap();
    /// 
    /// // process -> Process { handle: 0x458, name: "cheatengine-x86_64.exe", id: 24456 }
    /// // read struct -> RandomThreeInts { x: 255, y: 0, z: 16987320 }
    /// println!("process -> {process:?}");
    /// println!("read struct -> {random_struct:?}");
    /// ```
    pub fn new_from_name(process_name: &str) -> Option<Self>
    {
        match list_processes()
        {
            None => None,
            Some(processes) =>
            {
                for (id, name) in processes
                {
                    if name.to_lowercase().trim() == process_name.to_lowercase().trim() {return Some(Self{handle: unsafe{OpenProcess(PROCESS_ALL_ACCESS, 0, id)}, name, id})}
                }
                None
            }
        }
    }
    /// ## EN
    /// Determines if process runing under of x64 processor.<br/>  
    /// Returns [`Option`] containing [`bool`] if operation successed, otherwhise returns [`None`].
    /// #### Example:
    /// ```
    /// let process: Process = Proces::new_from_id(0x39EC);
    /// let process_is_x64: bool = process.is_x64().unwrap();
    /// 
    /// // true || false
    /// println!("{process_is_x64}");
    /// ```
    /// ## RU
    /// Проверяет запущен ли процесс с зайдейстованием x64 процессора.<br/>
    /// Возвращает [`Option`], содержащий [`bool`] в случае успешной операции, в противном случае возвращает [`None`].
    /// #### Пример:
    /// ```
    /// let process: Process = Proces::new_from_id(0x39EC);
    /// let process_is_x64: bool = process.is_x64().unwrap();
    /// 
    /// // true || false
    /// println!("{process_is_x64}");
    /// ```
    pub fn is_x64(&self) -> Option<bool>
    {
        unsafe
        {
            let mut is_64_bit: i32 = 0;

            let is_64_check_successed: i32 = IsWow64Process(self.handle, &mut is_64_bit);
            if is_64_check_successed != 0 {Some(if is_64_bit != 0 {true} else {false})} else {None}
        }
    }

    /// ## EN
    /// Displays memory byte table to console like it's made in [`Cheat Engine`] memory viewer.</br>
    /// * If 2nd argument is `0` sets it to default `8`.
    /// * If 3rd argument is `0` sets it to default `16`.
    /// 
    /// Retrurns [`bool`] dependent on the success of the operation, table will be displayed if operation successed.
    /// #### Example:
    /// ```
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// 
    /// // Console output:
    /// // B2 B6 B2 40 6F 6A C4 9A 30 1F 33 A4 A5 01 DD 1F 
    /// // 5B D9 69 E2 B8 50 32 F8 24 26 26 5A 60 3F AE 3D
    /// // 56 4C A5 FA C6 C7 C7 5B C3 67 B8 EF A9 6B 6A 6A
    /// // FE 06 E3 F5 98 36 86 E8 43 B2 77 AD 6D E2 3D FE
    /// // 3B 8E 45 50 DB F6 61 A8 4D BB F6 C8 C5 4A 1F 95
    /// // A7 FC 67 A7 EF 2C 71 43 B6 46 CA C8 48 43 91 B6
    /// // 67 30 FF B2 BA 9B 25 6E 43 72 DF B4 B5 B5 CF E1
    /// // 32 2D C5 85 C7 FE FD FB D5 B1 6F 38 44 57 57 F7
    /// process.byte_table(0x07A500A4, 0, 0);
    /// ```
    /// ## RU
    /// Отображает байт-таблицу памяти в консоле как это реализовано в обозреватели памяти [`Cheat Engine`].</br>
    /// * Если 2-ой аргумент `0`, то устнавливается как `8` по умолчанию.
    /// * Eсли 3-ий аргумент `0`, то устанавливается его как `16` по умолчанию.
    /// 
    /// Возвращает [`bool`], зависящий от успешности выполнения операции. Таблица будет выведена если операция прошла успешно.
    /// #### Пример:
    /// ```
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// 
    /// // Console output:
    /// // B2 B6 B2 40 6F 6A C4 9A 30 1F 33 A4 A5 01 DD 1F 
    /// // 5B D9 69 E2 B8 50 32 F8 24 26 26 5A 60 3F AE 3D
    /// // 56 4C A5 FA C6 C7 C7 5B C3 67 B8 EF A9 6B 6A 6A
    /// // FE 06 E3 F5 98 36 86 E8 43 B2 77 AD 6D E2 3D FE
    /// // 3B 8E 45 50 DB F6 61 A8 4D BB F6 C8 C5 4A 1F 95
    /// // A7 FC 67 A7 EF 2C 71 43 B6 46 CA C8 48 43 91 B6
    /// // 67 30 FF B2 BA 9B 25 6E 43 72 DF B4 B5 B5 CF E1
    /// // 32 2D C5 85 C7 FE FD FB D5 B1 6F 38 44 57 57 F7
    /// process.byte_table(0x07A500A4, 0, 0);
    /// ```
    /// [`Cheat Engine`]: https://www.cheatengine.org/aboutce.php
    pub fn byte_table(&self, address: usize, mut string_count: u32, mut string_length: u32) -> bool
    {
        if string_count == 0 {string_count = 8;}
        if string_length == 0 {string_length = 16;}

        let mut bytes_vector: Vec<u8> = Vec::new();

        for offset in 0..(string_count * string_length) as usize
        {
            match self.read_memory::<u8>(address + offset)
            {
                None => {},
                Some(byte) => bytes_vector.push(byte)
            }
        }

        if bytes_vector.len() == (string_count * string_length) as usize
        {
            let mut counter: usize = 0;
            for _ in 0..string_count
            {
                for _ in 0..string_length
                {
                    print!("{}", &format!("{:#04X} ", bytes_vector[counter])[2..]);
                    counter += 1;
                }
                print!("\n");
            }
            true
        } else {false}
    }

    /// ## EN
    /// Allocates memory in process.<br/>
    /// * If 2nd argument is `0` sets it to default `4096`.
    /// * if 3rd argument is `0` sets it to default `MEM_COMMIT`.
    /// * If 4th argument is `0` sets it to default `PAGE_EXECUTE_READWRITE`.
    /// 
    /// Return [`Option`] containing [`usize`] address of allocation if operation successed, otherwise returns [`None`].
    /// #### Example:
    /// ```
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// let alloc: usize = process.alloc_memory(0, 2048, MEM_COMMIT, PAGE_EXECUTE_READWRITE).unwrap();
    ///
    /// // 0x2aa0000
    /// println!("0x{alloc:x}");
    /// ```
    /// ## RU
    /// Аллоцирует память в процессе.
    /// * Если 2-ой аргумент `0`, то устнавливается как `4096` по умолчанию.
    /// * Если 3-ой аргумент `0`, то устнавливается как `MEM_COMMIT` по умолчанию.
    /// * Если 4-ой аргумент `0`, то устнавливается как `PAGE_EXECUTE_READWRITE` по умолчанию.
    /// 
    /// Возвращает [`Option`], содержащий [`usize`] адрес на выделенный участок памяти если операция прошла успешно, иначе возвращает [`None`].
    /// ```
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// let alloc: usize = process.alloc_memory(0, 2048, MEM_COMMIT, PAGE_EXECUTE_READWRITE).unwrap();
    ///
    /// // 0x2aa0000
    /// println!("0x{alloc:x}");
    /// ```
    pub fn alloc_memory(&self, desired_address: usize, mut allocation_size: usize, mut allocation_type: u32, mut protection: u32) -> Option<usize>
    {
        if allocation_size == 0 {allocation_size = 4096;}
        if allocation_type == 0 {allocation_type = MEM_COMMIT;}
        if protection == 0 {protection = PAGE_EXECUTE_READWRITE;}

        unsafe
        {
            let allocation_region: *const () = VirtualAllocEx(self.handle, desired_address as _, allocation_size, allocation_type, protection);
            if !allocation_region.is_null() {Some(allocation_region as usize)} else {None}
        }
    }

    /// ## EN
    /// Frees region with allocated memory in process.
    /// * If 2nd argument is `0` frees memory of the entire page.
    /// * if 3rd argument is `0` sets it to default `MEM_RELEASE`.
    /// 
    /// Returns [`bool`] dependent on the success of the operation.
    /// #### Exmaple:
    /// ```
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// let alloc: usize = process.alloc_memory(0, 2048, 0, 0).unwrap();
    ///
    /// let free_successed: bool = process.free_memory(alloc, 0, 0);
    ///
    /// // true
    /// println!("{free_successed}");
    ///
    /// let free_successed: bool = process.free_memory(alloc, 0, 0);
    ///
    /// // false (Trying to free already released memory)
    /// println!("{free_successed}");
    /// ```
    /// ## RU
    /// Высвобождает регион с аллоцированной памятью в процессе.
    /// * Если 2-ой аргумент `0`, то высвобождает страницу полностью.
    /// * Если 3-ой аргумент `0`, то устнавливается как `MEM_RELEASE` по умолчанию.
    /// 
    /// Возвращает [`bool`], зависящий от успешности выполнения операции.
    /// #### Пример:
    /// ```
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// let alloc: usize = process.alloc_memory(0, 2048, 0, 0).unwrap();
    ///
    /// let free_successed: bool = process.free_memory(alloc, 0, 0);
    ///
    /// // true
    /// println!("{free_successed}");
    ///
    /// let free_successed: bool = process.free_memory(alloc, 0, 0);
    ///
    /// // false (Trying to free already released memory)
    /// println!("{free_successed}");
    /// ```
    pub fn free_memory(&self, allocation_address: usize, allocation_size: usize, mut free_type: u32) -> bool
    {
        if free_type == 0 {free_type = MEM_RELEASE};

        unsafe
        {
            let memory_free_successed: i32 = VirtualFreeEx(self.handle, allocation_address as _, allocation_size, free_type);
            if memory_free_successed != 0 {true} else {false}
        }
    }

    /// ## EN
    /// Finds and gathers process modules matching the filter.<br/>
    /// Returns [`Option`] containing [`Vec`] with `Module`objects if operation successed, otherwise returns [`None`].
    /// #### Example:
    /// ```
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// let modules: Vec<Module> = process.list_modules(LIST_MODULES_ALL).unwrap();
    /// 
    /// // 64
    /// println!("{}", modules.len());
    /// 
    /// // Module { base_address: 0x400000, size_of_image: 17895424, entry_point: 0x403de0, name: "cheatengine-x86_64.exe" }
    /// // Module { base_address: 0x7ffabfa90000, size_of_image: 2179072, entry_point: 0x0, name: "ntdll.dll" }
    /// // ...
    /// // Module { base_address: 0x7ffab9e90000, size_of_image: 1769472, entry_point: 0x7ffab9ef7ea0, name: "WindowsCodecs.dll" }
    /// for module in modules
    /// {
    ///     println!{"{module:?}"};
    /// }
    /// ```
    /// ## RU
    /// Находит и собирает модули процесса соответствующие фильтру.<br/>
    /// Возвращает [`Option`], содержащий [`Vec`] с объектами `Module` если операция прошла успешно, иначе возвращает [`None`].
    /// #### Пример:
    /// ```
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// let modules: Vec<Module> = process.list_modules(LIST_MODULES_ALL).unwrap();
    /// 
    /// // 64
    /// println!("{}", modules.len());
    /// 
    /// // Module { base_address: 0x400000, size_of_image: 17895424, entry_point: 0x403de0, name: "cheatengine-x86_64.exe" }
    /// // Module { base_address: 0x7ffabfa90000, size_of_image: 2179072, entry_point: 0x0, name: "ntdll.dll" }
    /// // ...
    /// // Module { base_address: 0x7ffab9e90000, size_of_image: 1769472, entry_point: 0x7ffab9ef7ea0, name: "WindowsCodecs.dll" }
    /// for module in modules
    /// {
    ///     println!{"{module:?}"};
    /// }
    /// ```
    pub fn list_modules(&self, filter: u32) -> Option<Vec<Module>>
    {
        let mut modules_vec: Vec<Module> = Vec::new();

        let process_modules: [*const (); 4096] = [0 as _; 4096];
        let bytes_returned: u32 = 0;

        unsafe
        {
            match EnumProcessModulesEx(self.handle, &process_modules as _, std::mem::size_of_val(&process_modules) as _, &bytes_returned, filter)
            {
                0 => None,
                _ =>
                {
                    for module_id in 0..(bytes_returned / std::mem::size_of::<*const ()>() as u32) as _
                    {
                        let mut current_module: Module = Module{base_address: 0 as _, size_of_image: 0, entry_point: 0 as _, name: "".to_string()};

                        match GetModuleInformation(self.handle, process_modules[module_id], &mut current_module as _, std::mem::size_of::<Module>() as _)
                        {
                            0 => {},
                            _ => 
                            {
                                let module_name_raw: [u16; MODULE_NAME_SIZE] = [0; MODULE_NAME_SIZE];
                                GetModuleBaseNameW(self.handle, current_module.base_address, &module_name_raw as _, std::mem::size_of_val(&module_name_raw) as _);

                                let module_name: String = String::from_utf16_lossy(&module_name_raw).trim_end_matches('\0').to_string();
                                if !module_name.is_empty()
                                {
                                    current_module.name = module_name;
                                    modules_vec.push(current_module);
                                }
                            }
                        }
                    }
                    Some(modules_vec)
                }
            }
        }
    }

    /// ## EN
    /// Gets information about module in process.<br/>
    /// Returns [`Option`] containing `Module` object if operation successed, otherwise returns [`None`].
    /// #### Example:
    /// ```
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// let kernel_module: Module = process.get_module("kernel32.dll").unwrap();
    ///
    /// // Module { base_address: 0x7fff967f0000, size_of_image: 794624, entry_point: 0x7fff96802710, name: "KERNEL32.DLL" }
    /// println!("{:?}", kernel_module);
    /// ```
    /// ## RU
    /// Получает информацю о модуле в процессe.<br/>
    /// Возвращает [`Option`], содержащий объект `Module` в cлучае успешной операции, в противном случае возвращает [`None`].
    /// #### Пример:
    /// ```
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// let kernel_module: Module = process.get_module("kernel32.dll").unwrap();
    ///
    /// // Module { base_address: 0x7fff967f0000, size_of_image: 794624, entry_point: 0x7fff96802710, name: "KERNEL32.DLL" }
    /// println!("{:?}", kernel_module);
    /// ```
    pub fn get_module(&self, module_name: &str) -> Option<Module>
    {
        match self.list_modules(LIST_MODULES_ALL)
        {
            None => None,
            Some(modules) => 
            {
                for module in modules
                {
                    if module.name.to_lowercase().trim() == module_name.to_string().to_lowercase().trim() {return Some(module)}
                }
                None
            }
        }
    }

    /// ## EN
    /// Finds and gathers process memory pages.<br/>
    /// Returns [`Option`] containing [`Vec`] with `MemoryInformation`objects if operation successed, otherwise returns [`None`].
    /// #### Example:
    /// ```
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// let memory_pages: Vec<MemoryInformation> = process.list_memory_pages().unwrap();
    ///
    /// // MemoryInformation { base_address: 118947840, allocation_base: 118947840, allocation_protection: 2, alignment_1: 0, region_size: 90112, state: 4096, protect: 2, memory_type: 262144, alignment_2: 0 } 
    /// // MemoryInformation { base_address: 119037952, allocation_base: 0, allocation_protection: 0, alignment_1: 0, region_size: 40960, state: 65536, protect: 1, memory_type: 0, alignment_2: 0 }
    /// // ...
    /// // MemoryInformation { base_address: 190906368, allocation_base: 190906368, allocation_protection: 4, alignment_1: 0, region_size: 4096, state: 4096, protect: 4, memory_type: 131072, alignment_2: 0 }   
    /// for memory_page in memory_pages
    /// {
    ///     println!("{memory_page:?}");
    /// }
    /// ```
    /// ## RU
    /// Находит и собирает участки памяти в процессе.<br/>
    /// Возвращает [`Option`], содержащий [`Vec`] с объектами `Module` если операция прошла успешно, иначе возвращает [`None`].
    /// #### Пример:
    /// ```
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// let memory_pages: Vec<MemoryInformation> = process.list_memory_pages().unwrap();
    ///
    /// // MemoryInformation { base_address: 118947840, allocation_base: 118947840, allocation_protection: 2, alignment_1: 0, region_size: 90112, state: 4096, protect: 2, memory_type: 262144, alignment_2: 0 } 
    /// // MemoryInformation { base_address: 119037952, allocation_base: 0, allocation_protection: 0, alignment_1: 0, region_size: 40960, state: 65536, protect: 1, memory_type: 0, alignment_2: 0 }
    /// // ...
    /// // MemoryInformation { base_address: 190906368, allocation_base: 190906368, allocation_protection: 4, alignment_1: 0, region_size: 4096, state: 4096, protect: 4, memory_type: 131072, alignment_2: 0 }   
    /// for memory_page in memory_pages
    /// {
    ///     println!("{memory_page:?}");
    /// }
    /// ```
    pub fn list_memory_pages(&self) -> Option<Vec<MemoryInformation>>
    {
        let mut memory_pages_vec: Vec<MemoryInformation> = Vec::new();
        
        let mut memory_page_info: Option<MemoryInformation> = self.get_memory_page(0);
        while let Some(memory_info) = memory_page_info
        {
            memory_pages_vec.push(memory_info);
            memory_page_info = self.get_memory_page(memory_info.base_address as usize + memory_info.region_size as usize);
        }

        if memory_pages_vec.len() != 0 {Some(memory_pages_vec)} else {None}
    }

    /// ## EN
    /// Gets information about memory page in process.<br/>
    /// Returns [`Option`] containing `MemoryInformation` object if operation successed, otherwise returns [`None`].
    /// #### Example:
    /// ```
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// let process_base_memory_info: MemoryInformation = process.get_memory_page(0x10000).unwrap();
    ///
    /// // MemoryInformation { base_address: 65536, allocation_base: 65536, allocation_protection: 4, alignment_1: 0, region_size: 65536, state: 4096, protect: 4, memory_type: 262144, alignment_2: 0 }
    /// println!("{:?}", process_base_memory_info);
    /// ```
    /// ## RU
    /// Получает информацю об участке памяти в процессe.<br/>
    /// Возвращает [`Option`], содержащий объект `MemoryInformation` в cлучае успешной операции, в противном случае возвращает [`None`].
    /// #### Пример:
    /// ```
    /// let process: Process = Process::new_from_name("cheatengine-x86_64.exe").unwrap();
    /// let process_base_memory_info: MemoryInformation = process.get_memory_page(0x10000).unwrap();
    ///
    /// // MemoryInformation { base_address: 65536, allocation_base: 65536, allocation_protection: 4, alignment_1: 0, region_size: 65536, state: 4096, protect: 4, memory_type: 262144, alignment_2: 0 }
    /// println!("{:?}", process_base_memory_info);
    /// ```
    pub fn get_memory_page(&self, address: usize) -> Option<MemoryInformation>
    {
        let mut memory_information: MemoryInformation = MemoryInformation {base_address: 0, allocation_base: 0, allocation_protection: 0, alignment_1: 0, region_size: 0, state: 0, protect: 0, memory_type: 0, alignment_2: 0};

        unsafe
        {
            let virtual_querry_successsed: usize = VirtualQueryEx(self.handle, address as _, &mut memory_information as _, std::mem::size_of::<MemoryInformation>());
            if virtual_querry_successsed != 0 {Some(memory_information)} else {None}
        }
    }

    /// ## EN
    /// Reads process memory at the specified address.<br/>
    /// Return [`Option`] containing [`<T>`] type if operation successed, otherwise return [`None`].
    /// #### Example:
    /// ```
    /// #[derive(Debug)]
    /// struct PlayerLookVec
    /// {
    ///     yaw: f32,
    ///     pitch: f32
    /// }
    /// 
    /// let process: Process = Proces::new_from_id(0x39EC);
    /// let player_view_angle: PlayerLookVec = process.read_memory::<PlayerLookVec>(0x7FF68DC90);
    /// 
    /// // PlayerViewAngle {yaw: 30.0, pitch: -90.0}
    /// println!("{player_view_angle:?}");
    /// ```
    /// ## RU
    /// Читает память процесса по указаному адресу.<br/>
    /// Возвращает [`Option`], содержащий [`<T>`] тип в случае успешной операции, в противном случае возвращает [`None`].
    /// #### Пример:
    /// ```
    /// #[derive(Debug)]
    /// struct PlayerLookVec
    /// {
    ///     yaw: f32,
    ///     pitch: f32
    /// }
    /// 
    /// let process: Process = Proces::new_from_id(0x39EC);
    /// let player_view_angle: PlayerLookVec = process.read_memory::<PlayerLookVec>(0x7FF68DC90);
    /// 
    /// // PlayerViewAngle { yaw: 30.0, pitch: -90.0 }
    /// println!("{player_view_angle:?}");
    /// ```
    /// [`<T>`]: https://doc.rust-lang.org/book/ch10-01-syntax.html
    pub fn read_memory<T>(&self, read_address: usize) -> Option<T>
    {
        unsafe
        {
            let mut buffer: T = std::mem::zeroed::<T>();

            let read_successed: i32 = ReadProcessMemory(self.handle, read_address as _, &mut buffer as *const _ as _, std::mem::size_of::<T>(), 0 as _);
            if read_successed != 0 {Some(buffer)} else {None}
        }
    }

    /// ## EN
    /// Writes  [`<T>`] value to process memory at the specified address.<br/>
    /// Returns [`bool`] dependent on the success of the operation.
    /// #### Example:
    /// ```
    /// struct PlayerLookVec
    /// {
    ///     yaw: f32,
    ///     pitch: f32
    /// }
    /// 
    /// let process: Process = Process::new_from_id(0x39EC);
    /// process.write_memory(0x7FF68DC90, PlayerLookVec{yaw: 20f32, pitch: 50f32});
    /// ```
    /// ## RU
    /// Записывает [`<T>`] значение в память процесса по указаному адресу.<br/>
    /// Возвращает [`bool`], зависящий от успешности выполнения операции.
    /// #### Пример:
    /// ```
    /// struct PlayerLookVec
    /// {
    ///     yaw: f32,
    ///     pitch: f32
    /// }
    /// 
    /// let process: Process = Process::new_from_id(0x39EC);
    /// process.write_memory(0x7FF68DC90, PlayerLookVec{yaw: 20f32, pitch: 50f32});
    /// ```
    /// [`<T>`]: https://doc.rust-lang.org/book/ch10-01-syntax.html
    pub fn write_memory<T>(&self, write_adders: usize, value: T) -> bool
    {
        unsafe
        {
            let write_successed: i32 = WriteProcessMemory(self.handle, write_adders as _, &value as *const _ as _, std::mem::size_of::<T>(), 0 as _);
            if write_successed != 0 {true} else {false}
        }
    }
}

///## EN
/// Finds and gathers IDs and names of active processes.<br/>
/// Retrurns [`Option`] with [`Vec`] containing tuple with [`u32`] ID and [`String`] name of process if operation successed, otherwise returns [`None`].
/// #### Example:
/// ```
/// let active_processes: Vec<(u32, String)> = list_prcesses().unwrap();
/// 
/// // [(1352, "lsass.exe"), (1464, "svchost.exe"), ..., (22328, "cargo.exe"), (8576, "vctip.exe"), (23076, "readprm.exe")]]
/// println!("{active_processes:?}");
/// ```
/// ## RU
/// Находит и собирает ID и имена активных процессов.<br/>
/// Возвращает [`Option`], содержащий [`Vec`], содержащий кортеж с [`u32`] ID и [`String`] именем процесса если операция успешна, иначе возвращает [`None`].
/// #### Пример:
/// ```
/// let active_processes: Vec<(u32, String)> = list_prcesses().unwrap();
/// 
/// // [(1352, "lsass.exe"), (1464, "svchost.exe"), ..., (22328, "cargo.exe"), (8576, "vctip.exe"), (23076, "readprm.exe")]]
/// println!("{active_processes:?}");
/// ```
pub fn list_processes() -> Option<Vec<(u32, String)>>
{
    let mut processes_vec: Vec<(u32, String)> = Vec::new();

    let process_ids: [u32; 4096] = [0; 4096];
    let bytes_returned: u32 = 0;

    unsafe
    {
        match EnumProcesses(&process_ids as _, std::mem::size_of_val(&process_ids) as _, &bytes_returned)
        {
            0 => None,
            _ =>
            {
                for process_id in 0..(bytes_returned / std::mem::size_of::<u32>() as u32) as _
                {
                    let process_handle: *const () = OpenProcess(PROCESS_ALL_ACCESS, 0, process_ids[process_id]);

                    let file_name_raw: [u16; PATH_SIZE] = [0; PATH_SIZE];
                    GetProcessImageFileNameW(process_handle, &file_name_raw as _, PATH_SIZE as _);

                    let file_name: String = String::from_utf16_lossy(&file_name_raw).trim_end_matches('\0').to_string();
                    match file_name.split("\\").last()
                    {
                        None => {},
                        Some(name) => {if !name.is_empty() {processes_vec.push((process_ids[process_id], name.to_string()))}}
                    }
                }
                Some(processes_vec)
            }
        }
    }
}
