pub struct Chunks<E, I: Iterator<Item=Result<u8, E>> + ?Sized> {
    data: Vec<u8>,
    sum: u32,
    iter: I,
}

pub trait Chunkable<E> where Self: Iterator<Item=Result<u8, E>> {
    fn chunks(self) -> Chunks<E, Self>;
}

impl<E,I> Chunkable<E> for I where I: Sized+Iterator<Item=Result<u8, E>> {
    fn chunks(self) -> Chunks<E, Self> {
        Chunks {
            data: Vec::new(),
            sum: 1,
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

            // update sum: add the new byte
            self.sum += x as u32;

            // update sum: remove byte that's leaving the rolling sum if needed
            let len = self.data.len();
            if len >= 8196 {
                if let Some(old) = self.data.get(len - 8196) {
                    self.sum -= old.clone() as u32;
                }
            }

            // check whether to break the chunk
            if self.sum % 4096 == 0 {
                self.sum = 1;
                let mut out = Vec::new();
                out.append(&mut self.data);
                return Some(Ok(out));
            }
        }
        
        // return the chunk we have so far
        if self.data.len() != 0 {
            let mut out = Vec::new();
            out.append(&mut self.data);
            Some(Ok(out))
        } else {
            None
        }
    }
}

#[test]
fn chunk_test() {
    use std::iter::repeat; 

    let ok: Result<u8, ()> = Ok(1u8);
    let mut h1 = repeat(ok).take(5000).chunks();
    let r1 = h1.next();
    let r2 = h1.next();

    assert!(r1.is_some());
    let r1 = r1.unwrap();
    assert!(r1.is_ok());
    let r1 = r1.unwrap();
    assert_eq!(r1.len(), 4095);
    assert_eq!(r1.iter().map(|x| x.clone() as u32).sum::<u32>(), 4095);

    assert!(r2.is_some());
    let r2 = r2.unwrap();
    assert!(r2.is_ok());
    let r2 = r2.unwrap();
    assert_eq!(r2.len(), 5000-4095);
    assert_eq!(r2.iter().map(|x| x.clone() as u32).sum::<u32>(), 5000-4095);
}
