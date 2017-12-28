use std::mem;
use std::io::{self, Read};
use std::cmp;

use libc;

use net::cvt;
use net::AsInner;

#[derive(Debug)]
pub struct FileDesc {
    fd: libc::c_int,
}

pub fn max_len() -> usize {
    <libc::ssize_t>::max_value() as usize
}

impl FileDesc {
    pub fn new(fd: libc::c_int) -> FileDesc {
        FileDesc { fd: fd }
    }

    pub fn raw(&self) -> libc::c_int {
        self.fd
    }

    pub fn into_raw(self) -> libc::c_int {
        let fd = self.fd;
        mem::forget(self);
        fd
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = cvt(unsafe {
            libc::read(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                cmp::min(buf.len(), max_len())
            )
        })?;

        Ok(ret as usize)
    }

    pub fn read_to_end(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let mut me = self;
        (&mut me).read_to_end(buf)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let ret = cvt(unsafe {
            libc::write(
                self.fd,
                buf.as_ptr() as *const libc::c_void,
                cmp::min(buf.len(), max_len())
            )
        })?;

        Ok(ret as usize)
    }

    pub fn set_cloexec(&self) -> io::Result<()> {
        unsafe {
            cvt(libc::ioctl(self.fd, libc::FIOCLEX))?;
            Ok(())
        }
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        unsafe {
            let v = nonblocking as libc::c_int;
            cvt(libc::ioctl(self.fd, libc::FIONBIO, &v))?;
            Ok(())
        }
    }

    pub fn duplicate(&self) -> io::Result<FileDesc> {

        let make_filedesc = |fd| {
            let fd = FileDesc::new(fd);
            fd.set_cloexec()?;
            Ok(fd)
        };

        let fd = self.raw();

        cvt(unsafe { libc::fcntl(fd, libc::F_DUPFD, 0) }).and_then(make_filedesc)
    }
}

impl<'a> Read for &'a FileDesc {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read(buf)
    }
}

impl AsInner<libc::c_int> for FileDesc {
    fn as_inner(&self) -> &libc::c_int { &self.fd }
}

impl Drop for FileDesc {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.fd) };
    }
}
