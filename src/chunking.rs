const CHUNK_SIZE: usize = 512;

pub struct Chunks<E, I: Iterator<Item=Result<u8, E>> + ?Sized> {
    data: Vec<u8>,
    iter: I,
}

pub trait Chunkable<E> where Self: Iterator<Item=Result<u8, E>> {
    fn chunks(self) -> Chunks<E, Self>;
}

impl<E,I> Chunkable<E> for I where I: Sized+Iterator<Item=Result<u8, E>> {
    fn chunks(self) -> Chunks<E, Self> {
        Chunks {
            data: Vec::with_capacity(CHUNK_SIZE),
            iter: self
        }
    }
}

impl<E, I: Iterator<Item=Result<u8, E>>> Iterator for Chunks<E, I> {
    type Item = Result<Vec<u8>, E>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(x) = self.iter.next() {
            // abort on error
            let x = match x {
                Err(e) => return Some(Err(e)),
                Ok(r)  => r
            };
            self.data.push(x);

            // check whether to break the chunk
            if self.data.len() == CHUNK_SIZE {
                return Some(Ok(self.data.split_off(0)));
            }
        }
        
        // return the chunk we have so far
        if self.data.len() != 0 {
            Some(Ok(self.data.split_off(0)))
        } else {
            None
        }
    }
}

#[test]
fn chunk_test() {
    use std::iter::repeat; 

    let ok: Result<u8, ()> = Ok(1u8);
    let mut h1 = repeat(ok).take(600).chunks();
    let r1 = h1.next();
    let r2 = h1.next();

    assert!(r1.is_some());
    let r1 = r1.unwrap();
    assert!(r1.is_ok());
    let r1 = r1.unwrap();
    assert_eq!(r1.len(), 512);
    assert_eq!(r1.iter().map(|x| x.clone() as u32).sum::<u32>(), 512);

    assert!(r2.is_some());
    let r2 = r2.unwrap();
    assert!(r2.is_ok());
    let r2 = r2.unwrap();
    assert_eq!(r2.len(), 600-512);
    assert_eq!(r2.iter().map(|x| x.clone() as u32).sum::<u32>(), 600-512);
}
