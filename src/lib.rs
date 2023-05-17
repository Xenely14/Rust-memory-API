#![allow(dead_code)]

const PATH_SIZE: usize = 512;

pub const PROCESS_ALL_ACCESS: u32 = 0x001F0FFF;

#[link(name="kernel32")]
extern "C"
{
    pub fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> *const ();
    pub fn ReadProcessMemory(process_handle: *const (), read_address: *const (), buffer: *const (), buffer_size: usize, bytes_read: *const usize) -> i32;
    pub fn WriteProcessMemory(process_handle: *const (), write_address: *const (), buffer: *const (), buffer_size: usize, bytes_written : *const usize) -> i32;

    pub fn IsWow64Process(process_handle: *const (), is_64_bit: *const i32) -> i32;
}

#[link(name="psapi")]
extern "C"
{
    pub fn EnumProcesses(process_ids_list: *const u32, process_ids_list_size: u32, bytes_returned: *const u32) -> i32;
    pub fn GetProcessImageFileNameW(process_handle: *const (), image_file_name: *const u16, image_size: u32) -> u32;
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
/// ## EN
/// Structure of process module.<br/>
/// Contains module base address, size of image and entry point.
/// ## RU
/// Структура модуля процесса.<br/>
/// Содержит базовый адрес, размер изображения и точку входа модуля.
pub struct Module
{
    pub base_address: usize,
    pub size_of_image: usize,
    pub entry_point: usize
}
/// ## EN
/// Structure of process allowing to interact with virtual memory.<br/>
/// Contains process name, handle and ID (PID).
/// ## RU
/// Структура процесса, позволяющая взаимодейстовать с виртуальной памятью.<br/>
/// Содержит дескриптор, имя и ID (PID) процесса.
#[repr(C)]
#[derive(Debug, Clone)]
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
            Some(processes) =>
            {
                for (id, name) in processes
                {
                    if process_id == id {return Some(Self{handle: unsafe{OpenProcess(PROCESS_ALL_ACCESS, 0, id)}, name, id})}
                }
                None
            },
            None => {None}
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
            Some(processes) =>
            {
                for (id, name) in processes
                {
                    if name.to_lowercase().trim() == process_name.to_lowercase().trim() {return Some(Self{handle: unsafe{OpenProcess(PROCESS_ALL_ACCESS, 0, id)}, name, id})}
                }
                None
            },
            None => {None}
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
            0 => {None}
            _ =>
            {
                let active_processes_count: usize = (bytes_returned / std::mem::size_of::<u32>() as u32) as _;

                for process_id in 0..active_processes_count
                {
                    let process_handle: *const () = OpenProcess(PROCESS_ALL_ACCESS, 0, process_ids[process_id]);

                    let file_name_raw: [u16; PATH_SIZE] = [0; PATH_SIZE];
                    GetProcessImageFileNameW(process_handle, &file_name_raw as _, PATH_SIZE as _);

                    let file_name: String = String::from_utf16_lossy(&file_name_raw).trim_end_matches('\0').to_string();
                    match file_name.split("\\").last()
                    {
                        Some(name) => {if !name.is_empty() {processes_vec.push((process_ids[process_id], name.to_string()))}},
                        None => {}
                    }
                }
                Some(processes_vec)
            }
        }
    }
}