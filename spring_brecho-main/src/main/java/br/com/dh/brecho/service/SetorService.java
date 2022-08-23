package br.com.dh.brecho.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.dh.brecho.model.Setor;
import br.com.dh.brecho.repository.SetorRepository;

@Service
public class SetorService {

	@Autowired
	private SetorRepository setorRepository;

	public List<Setor> getAll() {

		return setorRepository.findAll();

	}

	public Optional<Setor> getById(Long id) {

		return setorRepository.findById(id);

	}

	public Setor post(Setor setor) {

		return setorRepository.save(setor);

	}

	public Optional<Setor> put(Setor setor) {

		if (setorRepository.existsById(setor.getId()))
			return Optional.ofNullable(setorRepository.save(setor));
		
		return Optional.empty();
		

	}

	public void delete(Long id) {

		if (setorRepository.existsById(id))
			setorRepository.deleteById(id);

	}
	
}
