use pin_project_lite::pin_project;
use smol::future::FutureExt;
use std::{
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll},
};

pin_project! {
    #[project = FutureStateProj]
    enum FutureState<F>
    where
        F: Future,
        F: Unpin,
    {
        Pending{fut: F},
        Done{out: F::Output},
        Empty{dummy: bool}
    }
}

pin_project! {
    pub struct JoinAll<F>
    where
    F: Future,
    F: Unpin,
    {
        state: Vec<FutureState<F>>,
    }
}

pub fn join_all<I>(it: I) -> JoinAll<I::Item>
where
    I: IntoIterator,
    I::Item: Future,
    I::Item: Unpin,
{
    let state: Vec<_> = it
        .into_iter()
        .map(|fut| FutureState::Pending { fut })
        .collect();
    JoinAll { state }
}

impl<F> Future for JoinAll<F>
where
    F: Future,
    F: Unpin,
{
    type Output = Vec<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut all_done = true;
        let this = self.project();
        for state in this.state.iter_mut() {
            if let FutureState::Pending { fut } = state {
                if let Poll::Ready(o) = fut.poll(cx) {
                    *state = FutureState::Done { out: o };
                } else {
                    all_done = false;
                }
            }
        }
        if !all_done {
            return Poll::Pending;
        }
        let ret = this
            .state
            .iter_mut()
            .map(|s| {
                let mut item = FutureState::Empty { dummy: true };
                mem::swap(s, &mut item);
                match item {
                    FutureState::Done { out } => out,
                    _ => unreachable!(),
                }
            })
            .collect();
        Poll::Ready(ret)
    }
}
